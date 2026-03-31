//! Route List — an ordered collection of route groups for failover.

use crate::dialplan::NumberTransform;

/// A Route List contains ordered Route Groups (trunk groups) for failover.
///
/// When a call matches a route pattern pointing to a route list, the router
/// tries each member in priority order until the call succeeds.
#[derive(Debug, Clone)]
pub struct RouteList {
    /// Unique identifier.
    id: String,
    /// Human-readable name.
    name: String,
    /// Optional description.
    description: Option<String>,
    /// Ordered members (route groups with per-member transforms).
    members: Vec<RouteListMember>,
}

/// A single member of a route list.
#[derive(Debug, Clone)]
pub struct RouteListMember {
    /// References a `TrunkGroup` ID.
    route_group_id: String,
    /// Priority — lower values are tried first.
    priority: u32,
    /// Optional per-member digit transform.
    transform: Option<NumberTransform>,
}

impl RouteListMember {
    /// Creates a new route list member.
    pub fn new(route_group_id: impl Into<String>, priority: u32) -> Self {
        Self {
            route_group_id: route_group_id.into(),
            priority,
            transform: None,
        }
    }

    /// Sets the per-member transform.
    #[must_use]
    pub fn with_transform(mut self, transform: NumberTransform) -> Self {
        self.transform = Some(transform);
        self
    }

    /// Returns the route group ID.
    pub fn route_group_id(&self) -> &str {
        &self.route_group_id
    }

    /// Returns the priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Returns the per-member transform, if any.
    pub fn transform(&self) -> Option<&NumberTransform> {
        self.transform.as_ref()
    }
}

impl RouteList {
    /// Creates a new empty route list.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            members: Vec::new(),
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Returns the route list ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the route list name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the description, if any.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Adds a member to the route list.
    pub fn add_member(&mut self, member: RouteListMember) {
        self.members.push(member);
    }

    /// Removes a member by route group ID.
    ///
    /// Returns `true` if a member was removed.
    pub fn remove_member(&mut self, route_group_id: &str) -> bool {
        let before = self.members.len();
        self.members
            .retain(|m| m.route_group_id != route_group_id);
        self.members.len() < before
    }

    /// Returns members sorted by priority (lowest first).
    pub fn ordered_members(&self) -> Vec<&RouteListMember> {
        let mut sorted: Vec<&RouteListMember> = self.members.iter().collect();
        sorted.sort_by_key(|m| m.priority);
        sorted
    }

    /// Returns the number of members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_list_create() {
        let rl = RouteList::new("rl-us", "US Route List")
            .with_description("Routes to US carriers");
        assert_eq!(rl.id(), "rl-us");
        assert_eq!(rl.name(), "US Route List");
        assert_eq!(rl.description(), Some("Routes to US carriers"));
        assert_eq!(rl.member_count(), 0);
    }

    #[test]
    fn test_route_list_add_members() {
        let mut rl = RouteList::new("rl-us", "US");
        rl.add_member(RouteListMember::new("tg-primary", 10));
        rl.add_member(RouteListMember::new("tg-secondary", 20));
        assert_eq!(rl.member_count(), 2);
    }

    #[test]
    fn test_route_list_ordering() {
        let mut rl = RouteList::new("rl-us", "US");
        rl.add_member(RouteListMember::new("tg-backup", 30));
        rl.add_member(RouteListMember::new("tg-primary", 10));
        rl.add_member(RouteListMember::new("tg-secondary", 20));

        let ordered = rl.ordered_members();
        assert_eq!(ordered[0].route_group_id(), "tg-primary");
        assert_eq!(ordered[1].route_group_id(), "tg-secondary");
        assert_eq!(ordered[2].route_group_id(), "tg-backup");
    }

    #[test]
    fn test_route_list_remove_member() {
        let mut rl = RouteList::new("rl-us", "US");
        rl.add_member(RouteListMember::new("tg-primary", 10));
        rl.add_member(RouteListMember::new("tg-secondary", 20));

        assert!(rl.remove_member("tg-primary"));
        assert_eq!(rl.member_count(), 1);
        assert!(!rl.remove_member("tg-nonexistent"));
    }

    #[test]
    fn test_route_list_member_transform() {
        let member = RouteListMember::new("tg-intl", 10)
            .with_transform(NumberTransform::add_prefix("011"));
        assert!(member.transform().is_some());
    }
}
