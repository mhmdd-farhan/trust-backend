import prisma from "../libs/db";
import { redis } from "../libs/db";
import {
    loginSchema,
    registerSchema,
    changePasswordSchema,
    sellerRegisterSchema,
} from "../schemas/auth";
import { z } from "zod";
import * as crypto from "../libs/crypto";
import * as jwt from "../libs/jwt";
import { google } from "googleapis";
import { oauth2Client } from "../libs/oauth";
import { uploadImage } from "../libs/uploadcare";

type RegisterSchema = z.infer<typeof registerSchema>;
type LoginSchema = z.infer<typeof loginSchema>;
type ChangePasswordSchema = z.infer<typeof changePasswordSchema>;
type SellerRegisterSchema = z.infer<typeof sellerRegisterSchema>

const processToken = async (
    refreshToken: string,
    isGenerated: boolean = false
) => {
    const isTokenExist = await prisma.userToken.findFirst({
        where: {
            token: { equals: refreshToken },
            expiresAt: { gte: new Date() },
        },
        include: {
            user: {
                select: {
                    userName: true
                }
            }
        }
    });

    if (!isTokenExist) {
        throw new Error("Token is Invalid or expired!");
    }

    await prisma.userToken.delete({
        where: { id: isTokenExist.id },
    });

    if (isGenerated) {
        
        const [accesToken, refreshToken] = await Promise.all([
            jwt.createAccesToken(isTokenExist.userId),
            jwt.createRefreshToken(isTokenExist.userId),
        ]);

        return { accesToken, refreshToken, userName: isTokenExist.user.userName };
    }

    return true;
};

export const register = async (userData: RegisterSchema) => {
    return await prisma.$transaction(async (db) => {
        const existingUser = await db.user.findFirst({
            where: {
                OR: [
                    {
                        userName: userData.username,
                    },
                    {
                        email: userData.email,
                    },
                ],
            },
        });

        if (existingUser) {
            throw new Error("Email or Username already registered!");
        }

        let role = await db.role.findFirst({
            where: {
                roleName: "USER",
            },
        });

        if (!role) {
            role = await db.role.create({
                data: {
                    roleName: "USER",
                    description: "This role can be buyer only",
                },
            });
        }

        const hashedPassword = await crypto.hashValue(userData.password);


        const newUser =  await db.user.create({
            data: {
                userName: userData.username,
                password: hashedPassword,
                email: userData.email,
                roles: {
                    create: {
                        roleId: role.id,
                    },
                },
            },
            select: {
                id: true,
                userName: true,
                email: true,
                roles: {
                    select: {
                        roleId: true,
                    },
                },
                carts: true
            },
        });
        // create new user cart
        const newUserCart = await db.cart.create({
            data: { userId: newUser.id }
        });

        return {
            ...newUser,
            cartId: newUserCart.id
        }
    });
};

export const login = async (userData: LoginSchema) => {
    const existingUser = await prisma.user.findUnique({
        where: {
            userName: userData.username,
        },
        select: {
            id: true,
            password: true,
            userName: true,
            roles: {
                select: {
                    role: {
                        select: {
                            roleName: true,
                        },
                    },
                },
            },
        },
    });

    const verifyPassword = await crypto.verifyvalue(
        userData.password,
        existingUser?.password
    );

    if (!existingUser || !verifyPassword) {
        throw Error(
            "User not found, input the correct email and password or register first"
        );
    }

    const [accessToken, refreshToken] = await Promise.all([
        jwt.createAccesToken(existingUser.id),
        jwt.createRefreshToken(existingUser.id),
    ]);

    // save refreshToken to database
    const currentDate = new Date();

    await prisma.userToken.create({
        data: { token: refreshToken, userId: existingUser.id, expiresAt: new Date(currentDate.setDate(currentDate.getDate() + 15)) },
    })

    return {
        userId: existingUser.id,
        userName: existingUser.userName,
        accesToken: accessToken,
        refreshToken: refreshToken,
        roles: existingUser.roles,
    };
};

export const profile = async (id: string) => {
    // Inline caching tecnique
    const isUserCached = await redis.get(id);

    const parsedUserData = JSON.parse(isUserCached as string);

    if (!isUserCached || parsedUserData.roles[0].role.roleName !== "SELLER") {
        const user = await prisma.user.findUnique({
            where: { id },
            select: {
                roles: {
                    select: {
                        role: {
                            select: {
                                roleName: true,
                            },
                        },
                    },
                },
                userName: true,
                email: true,
                avatarUrl: true,
                id: true,
            },
        });
        await redis.setex(id, 3600, JSON.stringify(user));
        return user;
    }
    
    return parsedUserData;
};

export const regenToken = async (refreshToken: string): Promise<any> => {
    return await processToken(refreshToken, true);
};

export const changePassword = async (userData: ChangePasswordSchema) => {
    const user = await prisma.user.findUnique({
        where: {
            userName: userData.userName,
            email: userData.email,
        },
    });

    if (!user) {
        throw new Error(
            "User not found. Can't change password, please enter the correct email and username"
        );
    }

    const newPassword = await crypto.hashValue(userData.newPassword);

    await prisma.user.update({
        data: {
            password: newPassword,
        },
        where: {
            userName: userData.userName,
            email: userData.email,
        },
    });

    return {
        message: "Success changed password",
    };
};

export const logOut = async (refreshToken: string) => {
    return await processToken(refreshToken);
};

export const googleAuthCallback = async (code: string) => {
    const { tokens } = await oauth2Client.getToken(code);

    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({
        auth: oauth2Client,
        version: "v2",
    });

    const { data } = await oauth2.userinfo.get();

    if (!data.email || !data.name || !data.id) {
        throw new Error("Failed get google user data");
    }

    let existingUser = await prisma.user.findUnique({
        where: {
            email: data.email,
        },
    });

    const role = await prisma.role.findFirst({
        where: {
            roleName: "USER",
        },
    });

    if (!existingUser) {
        existingUser = await prisma.user.create({
            data: {
                email: data.email,
                userName: data.name,
                password: data.id,
                roles: {
                    create: {
                        role: {
                            connect: {
                                id: role?.id,
                            },
                        },
                    },
                },
            },
        });
        const [accessToken, refreshToken] = await Promise.all([
            jwt.createAccesToken(existingUser.id),
            jwt.createRefreshToken(existingUser.id),
        ]);

        return {
            email: existingUser.email,
            userName: existingUser.userName,
            accessToken,
            refreshToken,
        };
    }

    return {
        message: "User Already",
    };
};

export const registerSeller = async (userData: SellerRegisterSchema) => {
    return await prisma.$transaction(async (db) => {
        const checkUser = await db.user.findFirst({
            where: {
                id: userData.userId,
            },
            include: {
                roles: {
                    include: {
                        role: {
                            select: {
                                roleName: true,
                                id: true
                            }
                        }
                    }
                }
            }
        });

        if (!checkUser || checkUser.roles.find((role) => role.role.roleName === "SELLER")) {
            throw new Error("User not found!, or allready has been seller");
        }

        let role = await db.role.findFirst({
            where: { roleName: userData.switchToRole },
        });

        if (!role) {
            role = await db.role.create({
                data: {
                    roleName: userData.switchToRole,
                    description: userData.description,
                },
            });
        }

        const previousRoleId = checkUser.roles.length > 0 ? checkUser.roles[0].role.id : null;

        if (previousRoleId) {
            // Delete older role
            await db.userRole.delete({
                where: {
                    userId_roleId: {
                        userId: userData.userId,
                        roleId: previousRoleId,
                    },
                },
            });
        };

        await db.userRole.upsert({
            where: {
                userId_roleId: {
                    userId: userData.userId,
                    roleId: role.id,
                },
            },
            update: {
                roleId: role.id,
            },
            create: {
                userId: userData.userId,
                roleId: role.id,
            },
        });

        const imageUuid = await uploadImage(userData.avatarUrl);

        const updatedUser = await db.user.update({
            where: { id: userData.userId },
            data: {
                avatarUrl: `https://ucarecdn.com/${imageUuid}`,
                description: userData.description,
            },
            select: {
                id: true,
                userName: true,
                email: true,
                description: true,
                avatarUrl: true,
                createdAt: true,
                updatedAt: true,
            },
        });

        return {
            message: "Switched to seller was successfully",
            updatedUser,
        };
    });
};
