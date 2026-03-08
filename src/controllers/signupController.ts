import bcrypt from "bcryptjs";
import { prisma } from "../utils/prisma";
import type { Request, Response } from "express";


interface SignupData {
    email: string,
    password: string,
    name: string,
    role: "STUDENT" | "INSTRUCTOR"
}


export const signupController = async (req: Request, res: Response): 
    Promise<void> => {
        try {
            const { email, password, name, role}: SignupData = req.body;

            const existingUser = await prisma.user.findUnique({
                where: {email}
            })

            if(existingUser) {
                res.status(409).json({
                    error: "User with this email already exists"
                });
                return;
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = await prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                    name,
                    role
                }
            });

            res.status(201).json({
                message: "User created successfully",
                user: {
                    id: newUser.id,
                    email: newUser.email,
                    name: newUser.name,
                    role: newUser.role,
                }
            });
        } catch (error) {
            res.status(500).json({
                error: "Server error"
            });
        }
}