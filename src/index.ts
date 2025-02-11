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

const customerSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().min(10)
});

const userSchema = z.object({
    customer_id: z.number(),
    email: z.string().email(),
    name: z.string().min(2),
    password: z.string().min(6),
    role: z.enum(["admin", "doctor", "staff", "patient"])
});

const specialtySchema = z.object({
    customer_id: z.number(),
    name: z.string().min(2),
    description: z.string().optional()
});

const doctorSchema = z.object({
    customer_id: z.number(),
    email: z.string().email(),
    name: z.string().min(2),
    password: z.string().min(6),
    crm: z.string().min(5),
    specialty_id: z.number()
});

const patientSchema = z.object({
    user_id: z.number(),
    customer_id: z.number(),
    date_of_birth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    gender: z.enum(["M", "F", "OTHER"]),
    address: z.string().optional(),
    health_insurance: z.string().optional()
});

const appointmentSchema = z.object({
    customer_id: z.number(),
    patient_id: z.number(),
    doctor_id: z.number(),
    slot_id: z.number(),
    status: z.enum(["scheduled", "confirmed", "completed", "cancelled"]),
    notes: z.string().optional()
});

const slotSchema = z.object({
    customer_id: z.number(),
    doctor_id: z.number(),
    start_time: z.string().datetime(),
    end_time: z.string().datetime(),
    is_available: z.boolean()
});

const app = new Hono<{ Bindings: CloudflareBindings }>();

app.use("/*", cors());

const secret =
    "Trabalho-Final-Banco-de-Dados-II-Desenvolvimento-de-uma-solução-SaaS-para-facilitar-o-agendamento-de-consultas-médicas";

app.use("/me", jwt({ secret }));
app.use("/customers", jwt({ secret }));
app.use("/doctors", jwt({ secret }));

app.post("/signup", async (c) => {
    try {
        const body = await c.req.json();
        const data = signupSchema.parse(body);

        const existingUser = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(data.email).first();

        if (existingUser) {
            return c.json({ error: "Email já cadastrado" }, 400);
        }

        const customerResult = await c.env.DB.prepare(
            "INSERT INTO customers (name, email, phone) VALUES (?, ?, ?) RETURNING id"
        )
            .bind(data.companyName, data.email, data.phone)
            .first();

        if (!customerResult) {
            throw new Error("Falha ao criar customer");
        }

        const customerId = customerResult.id;

        const passwordHash = await bcrypt.hash(data.password, 10);

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

app.get("/customers", async (c) => {
    const payload = c.get("jwtPayload");

    const results = await c.env.DB.prepare(`SELECT * FROM customers WHERE id = ?`).bind(payload.customerId).first();

    return c.json(results);
});

app.put("/customers/:id", async (c) => {
    const payload = c.get("jwtPayload");
    const id = c.req.param("id");
    const body = await c.req.json();
    const data = customerSchema.parse(body);

    const updates = Object.entries(data)
        .filter(([_, value]) => value !== undefined)
        .map(([key]) => `${key} = ?`)
        .join(", ");

    const values = Object.values(data);

    const result = await c.env.DB.prepare(
        `UPDATE customers SET ${updates} WHERE id = ? AND customer_id = ? RETURNING *`
    )
        .bind(...values, id, payload.customerId)
        .first();

    return result ? c.json(result) : c.json({ error: "Not found" }, 404);
});

app.delete("/customers/:id", async (c) => {
    const payload = c.get("jwtPayload");
    const id = c.req.param("id");

    await c.env.DB.prepare(`DELETE FROM customers WHERE id = ? AND customer_id = ?`).bind(id, payload.customerId).run();

    return c.json({ success: true });
});

app.post("/specialties", async (c) => {
    try {
        const validatedData = specialtySchema.parse(await c.req.json());

        const { customer_id, name, description } = validatedData;
        const result = await c.env.DB.prepare(
            `
            INSERT INTO specialties (customer_id, name, description)
            VALUES (?, ?, ?)
            `
        )
            .bind(customer_id, name, description)
            .run();

        return c.json({ id: result.meta.last_row_id, customer_id, name, description });
    } catch (err) {
        return c.json({ error: err }, 400);
    }
});

app.get("/specialties", async (c) => {
    const results = await c.env.DB.prepare(
        `
      SELECT id, customer_id, name, description FROM specialties
      `
    ).all();

    return c.json(results.results);
});

app.post("/doctors", async (c) => {
    try {
        const validatedData = doctorSchema.parse(await c.req.json());
        console.log("Dados validados:", validatedData);

        const { customer_id, email, name, password, crm, specialty_id } = validatedData;
        const password_hash = await bcrypt.hash(password, 10);

        const userResult = await c.env.DB.prepare(
            `INSERT INTO users (customer_id, email, name, password_hash, role) 
             VALUES (?, ?, ?, ?, 'doctor')
             RETURNING id`
        )
            .bind(customer_id, email, name, password_hash)
            .first();

        console.log("User Insert Result:", userResult);

        if (!userResult?.id) {
            throw new Error("Falha ao obter o ID do usuário criado");
        }

        const user_id = userResult.id;
        console.log("User ID gerado:", user_id);

        if (!crm || !specialty_id) {
            throw new Error("CRM ou especialidade inválidos");
        }

        const doctorResult = await c.env.DB.prepare(
            `INSERT INTO doctors (user_id, customer_id, crm, specialty_id) 
             VALUES (?, ?, ?, ?)`
        )
            .bind(user_id, customer_id, crm, specialty_id)
            .run();

        console.log("Doctor Insert Result:", doctorResult);

        return c.json({
            id: doctorResult.meta.lastInsertRowid,
            user_id,
            customer_id,
            crm,
            specialty_id
        });
    } catch (err) {
        console.error("Erro detalhado:", err);
        return c.json(
            {
                error: err instanceof Error ? err.message : "Erro desconhecido",
                details: err instanceof Error ? undefined : err
            },
            500
        );
    }
});

app.get("/doctors", async (c) => {
    try {
        const payload = c.get("jwtPayload");
        const customerId = payload?.customerId;
        if (!customerId) {
            return c.json({ error: "Customer ID não encontrado no payload" }, 400);
        }

        const results = await c.env.DB.prepare(
            `
            SELECT doctors.id, doctors.user_id, doctors.customer_id, doctors.crm, doctors.specialty_id, users.name AS user_name, users.email AS user_email
            FROM doctors
            JOIN users ON doctors.user_id = users.id
            WHERE doctors.customer_id = ?
            `
        )
            .bind(customerId)
            .all();

        return c.json(results.results);
    } catch (error) {
        console.error("Erro interno:", error);
        return c.json({ error: "Erro interno no servidor" }, 500);
    }
});

export default app;
