import { Request, Response, NextFunction } from 'express';

export default function ensureAuthenticated(
    request: Request,
    response: Response,
    next: NextFunction
): void {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
        throw new Error('JTW token is missing');
    }

    const token = authHeader;
}
