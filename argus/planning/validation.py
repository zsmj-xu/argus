"""Typed, user-actionable planning failures."""

from argus.domain.errors import ArgusV2Error


class PlanningError(ArgusV2Error):
    """Base class for deterministic plan compilation failures."""


class UnknownPluginError(PlanningError):
    pass


class MissingCapabilityError(PlanningError):
    pass


class AmbiguousCapabilityError(PlanningError):
    pass


class InvalidProviderError(PlanningError):
    pass


class CircularDependencyError(PlanningError):
    pass


class PlanningConfigError(PlanningError):
    pass
