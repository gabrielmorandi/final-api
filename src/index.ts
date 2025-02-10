import { Hono } from "hono";
import { jwt, sign } from "hono/jwt";
import { cors } from "hono/cors";
import { z } from "zod";
import bcrypt from "bcryptjs";

type CloudflareBindings = {
    DB: D1Database;
};

const signupSchema = z.object({
    companyName: z.string().min(2),
    adminName: z.string().min(2),
    email: z.string().email(),
    phone: z.string().min(10),
    password: z.string().min(6)
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string()
});

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.use("/*", cors());

const secret =
    "Trabalho-Final-Banco-de-Dados-II-Desenvolvimento-de-uma-solução-SaaS-para-facilitar-o-agendamento-de-consultas-médicas";

app.use("/me", jwt({ secret }));

app.post("/signup", async (c) => {
    try {
        const body = await c.req.json();
        const data = signupSchema.parse(body);

        const existingUser = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(data.email).first();

        if (existingUser) {
            return c.json({ error: "Email já cadastrado" }, 400);
        }

        // Inserir customer e obter ID
        const customerResult = await c.env.DB.prepare(
            "INSERT INTO customers (name, email, phone) VALUES (?, ?, ?) RETURNING id"
        )
            .bind(data.companyName, data.email, data.phone)
            .first();

        if (!customerResult) {
            throw new Error("Falha ao criar customer");
        }

        const customerId = customerResult.id;

        // Hash da senha
        const passwordHash = await bcrypt.hash(data.password, 10);

        // Criar usuário admin
        const userResult = await c.env.DB.prepare(
            `
                INSERT INTO users (customer_id, email, name, password_hash, role)
                VALUES (?, ?, ?, ?, 'admin')
                RETURNING id, customer_id, email, name, role
            `
        )
            .bind(customerId, data.email, data.adminName, passwordHash)
            .first();

        if (!userResult) {
            throw new Error("Falha ao criar usuário");
        }

        // Gerar token JWT com o secret consistente
        const token = await sign(
            {
                userId: userResult.id,
                customerId: userResult.customer_id,
                email: data.email,
                role: "admin"
            },
            secret
        );

        return c.json(
            {
                token,
                user: {
                    id: userResult.id,
                    customerId: userResult.customer_id,
                    email: userResult.email,
                    name: userResult.name,
                    role: userResult.role
                }
            },
            201
        );
    } catch (error) {
        console.error("Erro no signup:", error);
        if (error instanceof z.ZodError) {
            return c.json({ error: "Dados inválidos", details: error.errors }, 400);
        }
        return c.json({ error: "Erro interno do servidor" }, 500);
    }
});

app.post("/login", async (c) => {
    try {
        const body = await c.req.json();
        const data = loginSchema.parse(body);

        const user = await c.env.DB.prepare(
            `
                SELECT id, customer_id, email, name, password_hash, role
                FROM users
                WHERE email = ?
            `
        )
            .bind(data.email)
            .first();

        if (!user) {
            return c.json({ error: "Credenciais inválidas" }, 401);
        }

        const validPassword = await bcrypt.compare(data.password, user.password_hash as string);
        if (!validPassword) {
            return c.json({ error: "Credenciais inválidas" }, 401);
        }

        const token = await sign(
            {
                userId: user.id,
                customerId: user.customer_id,
                email: user.email,
                role: user.role
            },
            secret
        );

        return c.json({
            token,
            user: {
                id: user.id,
                customerId: user.customer_id,
                email: user.email,
                name: user.name,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Erro no login:", error);
        if (error instanceof z.ZodError) {
            return c.json({ error: "Dados inválidos", details: error.errors }, 400);
        }
        return c.json({ error: "Erro interno do servidor" }, 500);
    }
});

app.get("/me", async (c) => {
    const payload = c.get("jwtPayload");

    try {
        const user = await c.env.DB.prepare(
            `
                SELECT id, customer_id, email, name, role
                FROM users
                WHERE id = ?
            `
        )
            .bind(payload.userId)
            .first();

        if (!user) {
            return c.json({ error: "Usuário não encontrado" }, 404);
        }

        return c.json({
            user: {
                id: user.id,
                customerId: user.customer_id,
                email: user.email,
                name: user.name,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Erro ao buscar usuário:", error);
        return c.json({ error: "Erro interno do servidor" }, 500);
    }
});

export default app;
