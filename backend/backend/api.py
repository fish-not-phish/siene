from ninja_extra import NinjaExtraAPI
from users.api import router as users_router
from registry.api import router as registry_router
from registry.v2api import router as v2_router

# Internal API (session auth only — no public docs)
api = NinjaExtraAPI(
    title="Siene Internal API",
    version="1.0",
    docs_url=None,
    openapi_url=None,
)

api.add_router("/accounts/", users_router)
api.add_router("/registry/", registry_router)

# Public API v1 (robot Bearer auth — docs served by Next.js Scalar UI)
public_api = NinjaExtraAPI(
    title="Siene API",
    version="1.0",
    urls_namespace="public-api",
    description=(
        "The Siene public API. Authentication requires a **Robot Account** Bearer token.\n\n"
        "Create a robot account in your project or system settings, then pass the secret as:\n\n"
        "```\nAuthorization: Bearer <robot_secret>\n```\n\n"
        "Robot accounts are scoped — a project robot can only access its own project's resources. "
        "A system-level robot (project=null, permission `*/*`) has full access."
    ),
    docs_url=None,
    openapi_url="/openapi.json",
    openapi_extra={
        "info": {
            "x-logo": {
                "url": "/static/logo.png",
            }
        },
    },
)

public_api.add_router("/", v2_router)
