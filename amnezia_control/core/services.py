from .models import SystemSettings


def get_portal_link_lifetime_days() -> int:
    return SystemSettings.get_solo().portal_link_lifetime_days


def get_portal_renewal_cooldown_hours() -> int:
    return SystemSettings.get_solo().portal_renewal_cooldown_hours

