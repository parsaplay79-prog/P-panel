"""Verdent Platform — the admin panel's route package.

One router, assembled from one module per area of the product. The previous
single `api/routes/admin_panel.py` was 895 lines and had grown by accretion:
adding a page meant finding the right seam in a file that already contained
payment review, tickets, nodes, admins and test configs.

`router` is the only thing `api.main` imports. Each module owns its own paths
and permissions; nothing is shared by import order.
"""

from fastapi import APIRouter

from admin_panel.routes import (
    admins,
    audit_log,
    auth_routes,
    cloudflare_accounts,
    configurations,
    customers,
    dashboard,
    gaming,
    health,
    jobs_view,
    nodes,
    notifications_view,
    orders,
    payments,
    plans,
    pools,
    test_configs,
    tickets,
    usage,
)

router = APIRouter(prefix="/admin", tags=["admin-panel"])

# Order matters only for readability — every path below is distinct.
router.include_router(auth_routes.router)
router.include_router(dashboard.router)
router.include_router(orders.router)
router.include_router(payments.router)
router.include_router(customers.router)
router.include_router(configurations.router)
router.include_router(plans.router)
router.include_router(pools.router)
router.include_router(gaming.router)
router.include_router(nodes.router)
router.include_router(cloudflare_accounts.router)
router.include_router(admins.router)
router.include_router(tickets.router)
router.include_router(test_configs.router)
router.include_router(usage.router)
router.include_router(health.router)
router.include_router(audit_log.router)
router.include_router(notifications_view.router)
router.include_router(jobs_view.router)
