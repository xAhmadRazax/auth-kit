import type { Request, Response, NextFunction } from "express";
export const asyncHandler =
  (
    requestHandler: (
      req: Request,
      res: Response,
      next: NextFunction,
    ) => Promise<void>,
  ) =>
  (req: Request, res: Response, next: NextFunction) => {
    // // Promise.resolve ensures the handler always returns a Promise, even if it's not async
    Promise.resolve(requestHandler(req, res, next)).catch(next);
  };

function AsH() {}
