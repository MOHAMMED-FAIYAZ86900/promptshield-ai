
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from app import tools
from app.schemas import DocumentSummaryArguments, TicketArguments


class ToolValidationError(Exception):
    """Raised when arguments are invalid or no executor is registered."""


class ToolExecutionError(Exception):
    """Raised when an authorized tool fails during execution."""


class PreparedTool:
    """A registered tool whose arguments have passed validation."""

    def __init__(
        self,
        action: str,
        arguments: dict[str, Any],
        tool_function: Callable[..., Any],
    ):
        self.action = action
        self.arguments = arguments
        self.tool_function = tool_function


EXECUTORS: dict[
    str,
    tuple[type[BaseModel], Callable[..., Any]],
] = {
    "summarize_document": (
        DocumentSummaryArguments,
        tools.summarize_document,
    ),
    "create_support_ticket": (
        TicketArguments,
        tools.create_support_ticket,
    ),
}


def prepare_registered_tool(
    action: str,
    arguments: dict[str, Any],
) -> PreparedTool:
    """
    Resolve a registered tool and validate its arguments.

    This function never executes the tool.
    """

    registration = EXECUTORS.get(action)

    if registration is None:
        raise ToolValidationError(
            "No executor is registered for this action."
        )

    argument_model, tool_function = registration

    try:
        validated_arguments = argument_model.model_validate(arguments)
    except ValidationError as exc:
        raise ToolValidationError(
            "Tool arguments failed validation."
        ) from exc

    return PreparedTool(
        action=action,
        arguments=validated_arguments.model_dump(),
        tool_function=tool_function,
    )


def execute_prepared_tool(
    prepared: PreparedTool,
) -> Any:
    """
    Execute a previously prepared tool.

    Call this only after authorization and successful persistence
    of the execution-intent audit event.
    """

    try:
        return prepared.tool_function(**prepared.arguments)
    except Exception as exc:
        raise ToolExecutionError(
            "The authorized tool failed during execution."
        ) from exc


def execute_registered_tool(
    action: str,
    arguments: dict[str, Any],
) -> Any:
    """
    Backward-compatible convenience function.

    Note: This function validates and executes immediately.
    Use prepare_registered_tool() and execute_prepared_tool()
    when an audit-intent checkpoint is required.
    """

    prepared = prepare_registered_tool(action, arguments)
    return execute_prepared_tool(prepared)
