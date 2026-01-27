import { ReasonPhrases, StatusCodes } from "http-status-codes";

/**
 * @classdesc Comprehensive API error handling class for consistent error responses.
 * Implements detailed error reporting, operational error distinction, and
 * structured validation error handling.
 */
export class AppError extends Error {
  public readonly statusCode: StatusCodes;
  public readonly isOperational: boolean; // Flag for expected errors (e.g., user input)
  public readonly errorCode: string; // Unique code for client-side handling (optional, but recommended)
  // public readonly errors?: ValidationError[]; // For validation errors from libraries like express-validator
  // public readonly errors?: ZodError["issues"]; // For validation errors from libraries like express-validator
  public readonly errors?: Record<string, string>; // For validation errors from libraries like express-validator
  public readonly timestamp: string; // Added for logging and debugging
  public readonly context?: Record<string, unknown>; //Added for more context

  /**
   * @constructor
   * @param {StatusCodes} statusCode - The HTTP status code.
   * @param {string} message - A clear, human-readable error message.
   * @param {object} options - Configuration options for the error.
   * @param {boolean} [options.isOperational] - Indicates if the error is an expected application error.
   * @param {string} [options.errorCode] - A unique, machine-readable error code.
   * @param {ValidationError[]} [options.errors] - Validation errors from libraries like express-validator.
   */
  constructor(
    statusCode: StatusCodes,
    message: string = ReasonPhrases.INTERNAL_SERVER_ERROR, // Default message
    options: {
      errorCode?: string;
      errors?: Record<string, string>;
      stack?: string;
      isOperational?: boolean;
      context?: Record<string, unknown>;
    } = {}
  ) {
    super(message);

    this.name = this.constructor.name; // Set error name to class name
    this.statusCode = statusCode;
    this.message = message;
    this.isOperational = options.isOperational ?? true; // Default to true
    this.errorCode = options.errorCode || `ERR_${statusCode}`; // Default error code
    this.errors = options.errors;
    this.timestamp = new Date().toISOString();
    this.context = options.context;

    // Capture stack trace, excluding the constructor itself for cleaner logs
    if (options?.stack) {
      this.stack = options.stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Factory method for creating a BadRequestError.
   */
  static badRequest(
    message: string = ReasonPhrases.BAD_REQUEST,
    // errors?: ValidationError[],
    // errors?: ZodErrors["issues"],
    errors?: Record<string, string>,
    context?: Record<string, unknown>
  ) {
    return new AppError(StatusCodes.BAD_REQUEST, message, {
      errorCode: "ERR_BAD_REQUEST",
      errors,
      context,
    });
  }

  /**
   * Factory method for creating an UnauthorizedError.
   */
  static unauthorized(
    message: string = ReasonPhrases.UNAUTHORIZED,
    context?: Record<string, unknown>
  ) {
    return new AppError(StatusCodes.UNAUTHORIZED, message, {
      errorCode: "ERR_UNAUTHORIZED",
      context,
    });
  }

  /**
   * Factory method for creating a NotFoundError.
   */
  static notFound(
    message: string = ReasonPhrases.NOT_FOUND,
    context?: Record<string, unknown>
  ) {
    return new AppError(StatusCodes.NOT_FOUND, message, {
      errorCode: "ERR_NOT_FOUND",
      context,
    });
  }

  /**
   * Factory method for creating an InternalServerError.
   */
  static internal(
    message: string = ReasonPhrases.INTERNAL_SERVER_ERROR,
    context?: Record<string, unknown>
  ) {
    return new AppError(StatusCodes.INTERNAL_SERVER_ERROR, message, {
      isOperational: false, // Important:  Internal errors are usually *not* operational
      errorCode: "ERR_INTERNAL_SERVER",
      context,
    });
  }
  /**
   * Converts the ApiError object to a JSON representation suitable for
   * sending in an API response.  This method centralizes the response
   * formatting and ensures consistency.
   * @param {boolean} includeDetails -  Include the stack trace and context?  Useful for development,
   * but should be false in production for security.
   * @returns {object} - A JSON object representing the error.
   */
  toJSON(includeDetails: boolean = false): object {
    const baseResponse: Record<string, unknown> = {
      statusCode: this.statusCode,
      message: this.message,
      success: false, // Consistent success: false for errors
      errorCode: this.errorCode,
      timestamp: this.timestamp,
    };

    if (this.errors) {
      baseResponse.errors = this.errors;
    }
    if (includeDetails) {
      baseResponse.stack = this.stack;
      baseResponse.context = this.context;
    }

    return baseResponse;
  }
}

export interface AppErrorType extends AppError {}
