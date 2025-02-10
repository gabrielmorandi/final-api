import { Hono } from "hono";
import { jwt } from "hono/jwt";
import { cors } from "hono/cors";
import { z } from "zod";
import bcrypt from "bcrypt";

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

// Criação da aplicação Hono
const app = new Hono<{ Bindings: Bindings }>();

// Middleware de CORS
app.use("/*", cors());

// Middleware de autenticação JWT
const auth = jwt({
    secret: (c) => c.env.JWT_SECRET
});

// Rota de cadastro
app.post("/signup", async (c) => {
    try {
        const body = await c.req.json();
        const data = signupSchema.parse(body);

        // Verifica se o email já existe
        const existingUser = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(data.email).first();

        if (existingUser) {
            return c.json({ error: "Email já cadastrado" }, 400);
        }

        // Inicia transação
        const queries = [];

        // Cria novo customer
        queries.push(
            c.env.DB.prepare("INSERT INTO customers (name, email, phone) VALUES (?, ?, ?)").bind(
                data.companyName,
                data.email,
                data.phone
            )
        );

        // Obtém o ID do customer inserido
        queries.push(c.env.DB.prepare("SELECT last_insert_rowid() as id"));

        // Executa transação para criar customer
        const results = await c.env.DB.batch(queries);
        const customerId = results[1].results[0].id;

        // Hash da senha
        const passwordHash = await bcrypt.hash(data.password, 10);

        // Cria usuário admin
        await c.env.DB.prepare(
            `
        INSERT INTO users (customer_id, email, name, password_hash, role)
        VALUES (?, ?, ?, ?, 'admin')
      `
        )
            .bind(customerId, data.email, data.adminName, passwordHash)
            .run();

        // Gera token JWT
        const token = await jwt.sign(
            {
                customerId,
                email: data.email,
                role: "admin"
            },
            c.env.JWT_SECRET
        );

        return c.json(
            {
                token,
                user: {
                    customerId,
                    email: data.email,
                    name: data.adminName,
                    role: "admin"
                }
            },
            201
        );
    } catch (error) {
        if (error instanceof z.ZodError) {
            return c.json({ error: "Dados inválidos", details: error.errors }, 400);
        }
        console.error("Erro no signup:", error);
        return c.json({ error: "Erro interno do servidor" }, 500);
    }
});

// Rota de login
app.post("/login", async (c) => {
    try {
        const body = await c.req.json();
        const data = loginSchema.parse(body);

        // Busca usuário
        const user = await c.env.DB.prepare(
            `
        SELECT u.id, u.customer_id, u.email, u.name, u.password_hash, u.role
        FROM users u
        WHERE u.email = ?
      `
        )
            .bind(data.email)
            .first();

        if (!user) {
            return c.json({ error: "Credenciais inválidas" }, 401);
        }

        // Verifica senha
        const validPassword = await bcrypt.compare(data.password, user.password_hash);
        if (!validPassword) {
            return c.json({ error: "Credenciais inválidas" }, 401);
        }

        // Gera token JWT
        const token = await jwt.sign(
            {
                customerId: user.customer_id,
                userId: user.id,
                email: user.email,
                role: user.role
            },
            c.env.JWT_SECRET
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
        if (error instanceof z.ZodError) {
            return c.json({ error: "Dados inválidos", details: error.errors }, 400);
        }
        console.error("Erro no login:", error);
        return c.json({ error: "Erro interno do servidor" }, 500);
    }
});

// Rota protegida para verificar autenticação
app.get("/me", auth, async (c) => {
    const payload = c.get("jwtPayload");

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
});

export default app;
