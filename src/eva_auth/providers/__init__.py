"""OAuth providers for eva-auth."""

from eva_auth.providers.azure_ad_b2c import AzureADB2CProvider
from eva_auth.providers.microsoft_entra_id import MicrosoftEntraIDProvider

__all__ = ["AzureADB2CProvider", "MicrosoftEntraIDProvider"]
