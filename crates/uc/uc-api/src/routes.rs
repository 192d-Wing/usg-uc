//! API routing.

use crate::request::HttpMethod;
use std::collections::HashMap;

/// API route.
#[derive(Debug, Clone)]
pub struct Route {
    /// HTTP method.
    pub method: HttpMethod,
    /// Path pattern.
    pub path: String,
    /// Route name/ID.
    pub name: String,
    /// Route description.
    pub description: Option<String>,
    /// Whether authentication is required.
    pub auth_required: bool,
    /// Required permissions.
    pub permissions: Vec<String>,
}

impl Route {
    /// Creates a new route.
    pub fn new(method: HttpMethod, path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            name: name.into(),
            description: None,
            auth_required: true,
            permissions: Vec::new(),
        }
    }

    /// Creates a GET route.
    pub fn get(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, path, name)
    }

    /// Creates a POST route.
    pub fn post(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, path, name)
    }

    /// Creates a PUT route.
    pub fn put(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, path, name)
    }

    /// Creates a DELETE route.
    pub fn delete(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, path, name)
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets whether authentication is required.
    #[must_use]
    pub fn with_auth(mut self, required: bool) -> Self {
        self.auth_required = required;
        self
    }

    /// Adds a required permission.
    #[must_use]
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Returns whether this route matches the given method and path.
    pub fn matches(&self, method: HttpMethod, path: &str) -> Option<HashMap<String, String>> {
        if self.method != method {
            return None;
        }
        self.match_path(path)
    }

    /// Matches the path pattern.
    fn match_path(&self, path: &str) -> Option<HashMap<String, String>> {
        let pattern_parts: Vec<&str> = self.path.split('/').collect();
        let path_parts: Vec<&str> = path.split('/').collect();

        if pattern_parts.len() != path_parts.len() {
            return None;
        }

        let mut params = HashMap::new();

        for (pattern, actual) in pattern_parts.iter().zip(path_parts.iter()) {
            if let Some(param_name) = pattern.strip_prefix(':') {
                // Path parameter
                params.insert(param_name.to_string(), (*actual).to_string());
            } else if pattern.starts_with('{') && pattern.ends_with('}') {
                // Path parameter (alternative syntax)
                let param_name = &pattern[1..pattern.len() - 1];
                params.insert(param_name.to_string(), (*actual).to_string());
            } else if pattern != actual {
                return None;
            }
        }

        Some(params)
    }
}

/// API router.
#[derive(Debug, Default)]
pub struct Router {
    /// Registered routes.
    routes: Vec<Route>,
    /// Route prefix.
    prefix: String,
}

impl Router {
    /// Creates a new router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a router with a prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            routes: Vec::new(),
            prefix: prefix.into(),
        }
    }

    /// Adds a route.
    pub fn route(&mut self, route: Route) -> &mut Self {
        let mut route = route;
        if !self.prefix.is_empty() {
            route.path = format!("{}{}", self.prefix, route.path);
        }
        self.routes.push(route);
        self
    }

    /// Adds a GET route.
    pub fn get(&mut self, path: impl Into<String>, name: impl Into<String>) -> &mut Self {
        self.route(Route::get(path, name))
    }

    /// Adds a POST route.
    pub fn post(&mut self, path: impl Into<String>, name: impl Into<String>) -> &mut Self {
        self.route(Route::post(path, name))
    }

    /// Adds a PUT route.
    pub fn put(&mut self, path: impl Into<String>, name: impl Into<String>) -> &mut Self {
        self.route(Route::put(path, name))
    }

    /// Adds a DELETE route.
    pub fn delete(&mut self, path: impl Into<String>, name: impl Into<String>) -> &mut Self {
        self.route(Route::delete(path, name))
    }

    /// Returns all routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Finds a matching route.
    pub fn find(
        &self,
        method: HttpMethod,
        path: &str,
    ) -> Option<(&Route, HashMap<String, String>)> {
        for route in &self.routes {
            if let Some(params) = route.matches(method, path) {
                return Some((route, params));
            }
        }
        None
    }

    /// Returns the number of routes.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Merges another router into this one.
    pub fn merge(&mut self, other: Router) -> &mut Self {
        for route in other.routes {
            self.routes.push(route);
        }
        self
    }
}

/// Standard SBC API routes.
pub struct SbcRoutes;

impl SbcRoutes {
    /// Creates standard trunk management routes.
    pub fn trunks() -> Router {
        let mut router = Router::with_prefix("/api/v1/trunks");
        router
            .get("", "list_trunks")
            .get("/:id", "get_trunk")
            .post("", "create_trunk")
            .put("/:id", "update_trunk")
            .delete("/:id", "delete_trunk");
        router
    }

    /// Creates standard route management routes.
    pub fn routes() -> Router {
        let mut router = Router::with_prefix("/api/v1/routes");
        router
            .get("", "list_routes")
            .get("/:id", "get_route")
            .post("", "create_route")
            .put("/:id", "update_route")
            .delete("/:id", "delete_route");
        router
    }

    /// Creates call management routes.
    pub fn calls() -> Router {
        let mut router = Router::with_prefix("/api/v1/calls");
        router
            .get("", "list_calls")
            .get("/:id", "get_call")
            .delete("/:id", "hangup_call");
        router
    }

    /// Creates system management routes.
    pub fn system() -> Router {
        let mut router = Router::with_prefix("/api/v1/system");
        router
            .get("/health", "health_check")
            .get("/metrics", "get_metrics")
            .get("/config", "get_config")
            .put("/config", "update_config");
        router
    }

    /// Creates cluster management routes.
    ///
    /// ## NIST 800-53 Rev5: SC-24 (Fail in Known State)
    ///
    /// Provides endpoints for:
    /// - Cluster status and membership
    /// - Manual failover operations
    /// - Node draining for maintenance
    /// - State synchronization status
    pub fn cluster() -> Router {
        let mut router = Router::with_prefix("/api/v1/cluster");
        router
            // Cluster status
            .route(
                Route::get("/status", "cluster_status")
                    .with_description("Get overall cluster status and quorum information")
                    .with_permission("cluster:read"),
            )
            // Member management
            .route(
                Route::get("/members", "list_members")
                    .with_description("List all cluster members")
                    .with_permission("cluster:read"),
            )
            .route(
                Route::get("/members/:id", "get_member")
                    .with_description("Get details for a specific cluster member")
                    .with_permission("cluster:read"),
            )
            // Failover operations
            .route(
                Route::post("/failover", "initiate_failover")
                    .with_description("Initiate failover from a failed node")
                    .with_permission("cluster:admin"),
            )
            .route(
                Route::post("/failover/manual", "manual_failover")
                    .with_description("Manually failover to a specific target node")
                    .with_permission("cluster:admin"),
            )
            // Node lifecycle
            .route(
                Route::post("/drain", "drain_node")
                    .with_description("Drain sessions from local node for maintenance")
                    .with_permission("cluster:admin"),
            )
            .route(
                Route::post("/rejoin", "rejoin_cluster")
                    .with_description("Rejoin the cluster after maintenance")
                    .with_permission("cluster:admin"),
            )
            // State synchronization
            .route(
                Route::get("/state/sync-status", "sync_status")
                    .with_description("Get state synchronization status")
                    .with_permission("cluster:read"),
            )
            .route(
                Route::post("/state/force-sync", "force_sync")
                    .with_description("Force state synchronization with peers")
                    .with_permission("cluster:admin"),
            )
            // Snapshot management
            .route(
                Route::get("/state/snapshot", "get_snapshot")
                    .with_description("Get current state snapshot")
                    .with_permission("cluster:read"),
            )
            .route(
                Route::post("/state/snapshot/restore", "restore_snapshot")
                    .with_description("Restore state from a snapshot")
                    .with_permission("cluster:admin"),
            );
        router
    }

    /// Creates all standard SBC routes.
    pub fn all() -> Router {
        let mut router = Router::new();
        router
            .merge(Self::trunks())
            .merge(Self::routes())
            .merge(Self::calls())
            .merge(Self::system())
            .merge(Self::cluster());
        router
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_creation() {
        let route = Route::get("/api/v1/users", "list_users")
            .with_description("List all users")
            .with_permission("users:read");

        assert_eq!(route.method, HttpMethod::Get);
        assert_eq!(route.name, "list_users");
        assert!(route.auth_required);
    }

    #[test]
    fn test_route_no_auth() {
        let route = Route::get("/health", "health_check").with_auth(false);
        assert!(!route.auth_required);
    }

    #[test]
    fn test_route_matches() {
        let route = Route::get("/api/v1/users/:id", "get_user");

        let params = route.matches(HttpMethod::Get, "/api/v1/users/123");
        assert!(params.is_some());
        let params = params.unwrap();
        assert_eq!(params.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_route_no_match_method() {
        let route = Route::get("/api/v1/users", "list_users");
        let params = route.matches(HttpMethod::Post, "/api/v1/users");
        assert!(params.is_none());
    }

    #[test]
    fn test_route_no_match_path() {
        let route = Route::get("/api/v1/users", "list_users");
        let params = route.matches(HttpMethod::Get, "/api/v1/posts");
        assert!(params.is_none());
    }

    #[test]
    fn test_route_curly_brace_params() {
        let route = Route::get("/api/v1/users/{id}/posts/{post_id}", "get_user_post");

        let params = route.matches(HttpMethod::Get, "/api/v1/users/123/posts/456");
        assert!(params.is_some());
        let params = params.unwrap();
        assert_eq!(params.get("id"), Some(&"123".to_string()));
        assert_eq!(params.get("post_id"), Some(&"456".to_string()));
    }

    #[test]
    fn test_router_creation() {
        let router = Router::new();
        assert_eq!(router.route_count(), 0);
    }

    #[test]
    fn test_router_with_prefix() {
        let mut router = Router::with_prefix("/api/v1");
        router.get("/users", "list_users");

        assert_eq!(router.routes()[0].path, "/api/v1/users");
    }

    #[test]
    fn test_router_add_routes() {
        let mut router = Router::new();
        router
            .get("/users", "list_users")
            .post("/users", "create_user")
            .get("/users/:id", "get_user");

        assert_eq!(router.route_count(), 3);
    }

    #[test]
    fn test_router_find() {
        let mut router = Router::new();
        router
            .get("/users", "list_users")
            .get("/users/:id", "get_user");

        let result = router.find(HttpMethod::Get, "/users/123");
        assert!(result.is_some());
        let (route, params) = result.unwrap();
        assert_eq!(route.name, "get_user");
        assert_eq!(params.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_router_find_not_found() {
        let mut router = Router::new();
        router.get("/users", "list_users");

        let result = router.find(HttpMethod::Get, "/posts");
        assert!(result.is_none());
    }

    #[test]
    fn test_router_merge() {
        let mut router1 = Router::new();
        router1.get("/users", "list_users");

        let mut router2 = Router::new();
        router2.get("/posts", "list_posts");

        router1.merge(router2);
        assert_eq!(router1.route_count(), 2);
    }

    #[test]
    fn test_sbc_routes_trunks() {
        let router = SbcRoutes::trunks();
        assert_eq!(router.route_count(), 5);

        let result = router.find(HttpMethod::Get, "/api/v1/trunks/123");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "get_trunk");
    }

    #[test]
    fn test_sbc_routes_calls() {
        let router = SbcRoutes::calls();
        assert_eq!(router.route_count(), 3);
    }

    #[test]
    fn test_sbc_routes_system() {
        let router = SbcRoutes::system();

        let result = router.find(HttpMethod::Get, "/api/v1/system/health");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "health_check");
    }

    #[test]
    fn test_sbc_routes_cluster() {
        let router = SbcRoutes::cluster();

        // Test cluster status route
        let result = router.find(HttpMethod::Get, "/api/v1/cluster/status");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "cluster_status");

        // Test members list route
        let result = router.find(HttpMethod::Get, "/api/v1/cluster/members");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "list_members");

        // Test get member route with path param
        let result = router.find(HttpMethod::Get, "/api/v1/cluster/members/node-01");
        assert!(result.is_some());
        let (route, params) = result.unwrap();
        assert_eq!(route.name, "get_member");
        assert_eq!(params.get("id"), Some(&"node-01".to_string()));

        // Test failover route
        let result = router.find(HttpMethod::Post, "/api/v1/cluster/failover");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "initiate_failover");

        // Test drain route
        let result = router.find(HttpMethod::Post, "/api/v1/cluster/drain");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "drain_node");

        // Test sync status route
        let result = router.find(HttpMethod::Get, "/api/v1/cluster/state/sync-status");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.name, "sync_status");
    }

    #[test]
    fn test_sbc_routes_all() {
        let router = SbcRoutes::all();

        // Should have routes from all routers
        assert!(router.route_count() > 15); // trunks(5) + routes(5) + calls(3) + system(4) + cluster(10)

        // Test that routes from different routers are accessible
        let result = router.find(HttpMethod::Get, "/api/v1/trunks");
        assert!(result.is_some());

        let result = router.find(HttpMethod::Get, "/api/v1/cluster/status");
        assert!(result.is_some());
    }
}
