//go:build !darwin

package cli

// defaultRoutes gives no route. Only macOS reads the route table in this
// release, so the snapshot of another system holds no gateway and no default
// route of the v6 family.
func defaultRoutes() (v4, v6 defaultRoute) {
	return defaultRoute{}, defaultRoute{}
}
