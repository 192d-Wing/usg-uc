//! Attribute-based access control for the operator surface.
//!
//! Authorization is AWS-IAM-shaped: an action is `entity:verb` (e.g.
//! `phones:write`, `dialplans:read`), and a request is permitted iff the
//! subject's roles grant that action **and** the target site is in the
//! subject's site allowlist. Both dimensions come from the OIDC token:
//!
//! - `roles` — capability roles. A role is either a *managed* name
//!   (see `managed_role_patterns`, e.g. `fleet-admin`, `auditor`,
//!   `phones-admin`) or a raw IAM-style pattern (`phones:write`,
//!   `dialplans:*`, `*:read`,
//!   `*:*`). Keycloak can emit either, so policy is data-driven, not
//!   hard-coded per operator.
//! - `sites` — the site codes the roles apply to, or `["*"]` for the whole
//!   fleet.
//!
//! Back-compat: a token carrying the legacy `config-admin` OAuth scope is
//! treated as a full fleet admin (`*:*` on `*`).

use proto_jwt::Claims;

/// A config entity an action targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    Phones,
    Directory,
    TrunkGroups,
    DialPlans,
    Routing,
    SiteConfig,
    /// The site registry itself (list/register) — a fleet-level resource.
    Sites,
    /// Global templates + materialization — a fleet-level resource.
    Templates,
}

impl Entity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Phones => "phones",
            Self::Directory => "directory",
            Self::TrunkGroups => "trunkgroups",
            Self::DialPlans => "dialplans",
            Self::Routing => "routing",
            Self::SiteConfig => "site_config",
            Self::Sites => "sites",
            Self::Templates => "templates",
        }
    }

    /// Fleet-level entities aren't scoped to one site; acting on them
    /// requires the fleet (`*`) site grant.
    const fn is_fleet_level(self) -> bool {
        matches!(self, Self::Sites | Self::Templates)
    }
}

/// Read (GET) vs write (POST/PUT/DELETE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Read,
    Write,
}

impl Verb {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// A requested action: `entity:verb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    pub entity: Entity,
    pub verb: Verb,
}

impl Action {
    pub const fn new(entity: Entity, verb: Verb) -> Self {
        Self { entity, verb }
    }
}

/// Managed role names → the action patterns they grant. Patterns are
/// `entity:verb` with `*` wildcards on either side.
fn managed_role_patterns(role: &str) -> Option<&'static [&'static str]> {
    match role {
        // Full fleet access.
        "fleet-admin" | "config-admin" | "site-admin" => Some(&["*:*"]),
        // Read everything.
        "auditor" | "config-reader" => Some(&["*:read"]),
        // Per-entity admins.
        "phones-admin" => Some(&["phones:*"]),
        "directory-admin" => Some(&["directory:*"]),
        "trunk-admin" => Some(&["trunkgroups:*"]),
        "dialplan-admin" => Some(&["dialplans:*", "routing:*"]),
        _ => None,
    }
}

/// Does an action pattern (`entity:verb`, `*` allowed) match `action`?
fn pattern_matches(pattern: &str, action: Action) -> bool {
    let Some((ent, verb)) = pattern.split_once(':') else {
        return false;
    };
    (ent == "*" || ent == action.entity.as_str()) && (verb == "*" || verb == action.verb.as_str())
}

/// Does a single role grant `action`? A role is either a managed name or a
/// raw `entity:verb` pattern.
fn role_grants(role: &str, action: Action) -> bool {
    if let Some(patterns) = managed_role_patterns(role) {
        return patterns.iter().any(|p| pattern_matches(p, action));
    }
    // Unknown role string: treat it as a raw IAM-style action pattern.
    pattern_matches(role, action)
}

/// The authenticated operator's attributes, derived from token claims.
pub struct Subject {
    roles: Vec<String>,
    sites: Vec<String>,
    /// Legacy `config-admin` OAuth scope → full fleet admin.
    fleet_via_scope: bool,
}

impl Subject {
    /// Build from validated claims.
    #[must_use]
    pub fn from_claims(claims: &Claims) -> Self {
        Self {
            roles: claims.roles.clone(),
            sites: claims.sites.clone(),
            fleet_via_scope: claims.has_scope(crate::state::ADMIN_SCOPE),
        }
    }

    /// True if the subject's site allowlist covers `site` (or `*`).
    fn covers_site(&self, site: Option<&str>) -> bool {
        if self.sites.iter().any(|s| s == "*") {
            return true;
        }
        // A specific-site action with no site resolves to deny.
        site.is_some_and(|code| self.sites.iter().any(|s| s == code))
    }

    /// Decide whether the subject may perform `action` on `site`
    /// (`site` is `None` for fleet-level entities).
    #[must_use]
    pub fn permits(&self, action: Action, site: Option<&str>) -> bool {
        if self.fleet_via_scope {
            return true;
        }
        let action_ok = self.roles.iter().any(|r| role_grants(r, action));
        if !action_ok {
            return false;
        }
        // Fleet-level entities require the `*` site grant; site-scoped
        // entities require the target site (or `*`).
        if action.entity.is_fleet_level() {
            self.sites.iter().any(|s| s == "*")
        } else {
            self.covers_site(site)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(roles: &[&str], sites: &[&str]) -> Subject {
        Subject {
            roles: roles.iter().map(|s| (*s).to_string()).collect(),
            sites: sites.iter().map(|s| (*s).to_string()).collect(),
            fleet_via_scope: false,
        }
    }

    const PHONES_W: Action = Action::new(Entity::Phones, Verb::Write);
    const PHONES_R: Action = Action::new(Entity::Phones, Verb::Read);
    const DIAL_W: Action = Action::new(Entity::DialPlans, Verb::Write);

    #[test]
    fn fleet_admin_can_do_anything_anywhere() {
        let s = subject(&["fleet-admin"], &["*"]);
        assert!(s.permits(PHONES_W, Some("MUHJ")));
        assert!(s.permits(Action::new(Entity::Sites, Verb::Write), None));
    }

    #[test]
    fn site_admin_is_scoped_to_its_sites() {
        let s = subject(&["site-admin"], &["MUHJ"]);
        assert!(s.permits(PHONES_W, Some("MUHJ")));
        assert!(!s.permits(PHONES_W, Some("MPLS")), "other site denied");
        // site-admin is not fleet → can't touch fleet-level resources.
        assert!(!s.permits(Action::new(Entity::Sites, Verb::Write), None));
    }

    #[test]
    fn auditor_is_read_only() {
        let s = subject(&["auditor"], &["MUHJ", "MPLS"]);
        assert!(s.permits(PHONES_R, Some("MUHJ")));
        assert!(s.permits(PHONES_R, Some("MPLS")));
        assert!(!s.permits(PHONES_W, Some("MUHJ")), "auditor cannot write");
    }

    #[test]
    fn per_entity_admin_and_raw_patterns() {
        let phones = subject(&["phones-admin"], &["MUHJ"]);
        assert!(phones.permits(PHONES_W, Some("MUHJ")));
        assert!(
            !phones.permits(DIAL_W, Some("MUHJ")),
            "phones-admin can't touch dial plans"
        );

        // Raw IAM-style role pattern emitted directly by the IdP.
        let raw = subject(&["dialplans:write"], &["MUHJ"]);
        assert!(raw.permits(DIAL_W, Some("MUHJ")));
        assert!(!raw.permits(PHONES_W, Some("MUHJ")));
    }

    #[test]
    fn legacy_config_admin_scope_is_full_fleet() {
        let s = Subject {
            roles: vec![],
            sites: vec![],
            fleet_via_scope: true,
        };
        assert!(s.permits(PHONES_W, Some("ANY")));
        assert!(s.permits(Action::new(Entity::Templates, Verb::Write), None));
    }

    #[test]
    fn no_grant_is_denied() {
        let s = subject(&[], &["MUHJ"]);
        assert!(!s.permits(PHONES_R, Some("MUHJ")));
        let s2 = subject(&["phones-admin"], &[]); // role but no sites
        assert!(!s2.permits(PHONES_W, Some("MUHJ")));
    }
}
