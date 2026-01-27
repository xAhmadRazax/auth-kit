import { User } from "../services/user.service"; // or wherever your user type is

declare global {
  namespace Express {
    interface Request {
      user?: User; // optional because not every request has a logged-in user
    }
  }
}
