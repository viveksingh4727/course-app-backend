import type { NextFunction, Request, Response } from "express";
import jwt, { decode, type JwtPayload } from "jsonwebtoken";


interface jwtPayload {
    userId: string,
    email: string,
    role: string,
}

declare global {
    namespace Express {
        interface Request {
            userId?: string,
            role?: string,
            user?: JwtPayload,
        }
    }
}

export const authMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({
            error: "Unauthorized"
        })
        return;
    }
    
    const token = authHeader.substring(7);

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as jwtPayload;

    try {
        
        req.userId = decoded.userId;
        req.role = decoded.role;
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({
            error: "Invalid token"
        });
    }
};

export const requireRole = (requiredRole: string) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (req.role !== requiredRole) {
            res.status(403).json({
                error: "Forbidden"
            });
            return;
        }
        next();
    }
} 