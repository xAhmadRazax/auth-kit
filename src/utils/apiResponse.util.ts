import type { Response } from "express";
import { StatusCodes } from "http-status-codes";
export class ApiResponse<T> {
  public readonly statusCode: StatusCodes;
  public readonly message: string;
  public readonly success: boolean;
  public readonly data: T | null;

  /**
   * @constructor
   * @param {StatusCodes} statusCode - The HTTP status code for the response.
   * @param {string} message - A descriptive message for the response.
   * @param {T | null} data - The data payload (can be null for empty responses).
   */
  constructor(statusCode: StatusCodes, message: string, data: T | null = null) {
    this.statusCode = statusCode;
    this.message = message;
    this.success = true; // Consistent success: true for success
    this.data = data;
  }

  /**
   * Converts the ApiResponse object to a JSON representation.
   * @returns {object} - A JSON object representing the response.
   */
  toJSON(): object {
    return {
      statusCode: this.statusCode,
      message: this.message,
      success: this.success,
      data: this.data,
    };
  }

  static sendJSON<U>(
    res: Response,
    statusCode: StatusCodes,
    message: string,
    data: U | null = null,
    // success: boolean = true
  ) {
    return res
      .status(statusCode)
      .json(new ApiResponse<U>(statusCode, message, data).toJSON());
  }
}
