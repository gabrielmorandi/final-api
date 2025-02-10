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
    user_id: z.number(),
    customer_id: z.number(),
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

app.get("/dashboard", async (c) => {
    try {
        const payload = c.get("jwtPayload");

        // Buscar dados do cliente
        const customer = await c.env.DB.prepare("SELECT id, name, email, phone FROM customers WHERE id = ?")
            .bind(payload.customerId)
            .first();

        // Buscar médicos
        const doctors = await c.env.DB.prepare(
            `
            SELECT d.id, d.crm, d.name AS doctor_name, s.name AS specialty_name
            FROM doctors d
            JOIN specialties s ON d.specialty_id = s.id
            WHERE d.customer_id = ?
            `
        )
            .bind(payload.customerId)
            .all();

        // Buscar pacientes
        const patients = await c.env.DB.prepare(
            "SELECT id, name, date_of_birth, gender FROM patients WHERE customer_id = ?"
        )
            .bind(payload.customerId)
            .all();

        // Buscar agendamentos
        const appointments = await c.env.DB.prepare(
            `
            SELECT a.id, a.status, p.name AS patient_name, d.name AS doctor_name, a.created_at
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            JOIN doctors d ON a.doctor_id = d.id
            WHERE a.customer_id = ?
            `
        )
            .bind(payload.customerId)
            .all();

        // Buscar horários disponíveis
        const availableSlots = await c.env.DB.prepare(
            `
        SELECT s.start_time, s.end_time, d.name AS doctor_name
        FROM available_slots s
        JOIN doctors d ON s.doctor_id = d.id
        WHERE s.customer_id = ? AND s.is_available = 1
        `
        )
            .bind(payload.customerId)
            .all();

        return c.json({
            customer,
            doctors,
            patients,
            appointments,
            availableSlots
        });
    } catch (error) {
        console.error("Erro ao carregar o dashboard:", error);
        return c.json({ error: "Erro ao carregar o dashboard" }, 500);
    }
});

// Rotas CRUD Genéricas
const createCrudRoutes = (path: string, table: string, schema: z.ZodSchema) => {
    // Create
    app.post(`/${path}`, async (c) => {
        const payload = c.get("jwtPayload");
        const body = await c.req.json();
        const data = schema.parse({ ...body, customer_id: payload.customerId });

        const columns = Object.keys(data).join(", ");
        const values = Object.values(data);
        const placeholders = values.map(() => "?").join(", ");

        const result = await c.env.DB.prepare(`INSERT INTO ${table} (${columns}) VALUES (${placeholders}) RETURNING *`)
            .bind(...values)
            .first();

        return c.json(result);
    });

    // Read All
    app.get(`/${path}`, async (c) => {
        const payload = c.get("jwtPayload");
        const results = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE customer_id = ?`)
            .bind(payload.customerId)
            .all();

        return c.json(results);
    });

    // Read One
    app.get(`/${path}/:id`, async (c) => {
        const payload = c.get("jwtPayload");
        const id = c.req.param("id");
        const result = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE id = ? AND customer_id = ?`)
            .bind(id, payload.customerId)
            .first();

        return result ? c.json(result) : c.json({ error: "Not found" }, 404);
    });

    // Update
    app.put(`/${path}/:id`, async (c) => {
        const payload = c.get("jwtPayload");
        const id = c.req.param("id");
        const body = await c.req.json();
        const data = schema.parse(body);

        const updates = Object.entries(data)
            .filter(([_, value]) => value !== undefined)
            .map(([key]) => `${key} = ?`)
            .join(", ");

        const values = Object.values(data);

        const result = await c.env.DB.prepare(
            `UPDATE ${table} SET ${updates} WHERE id = ? AND customer_id = ? RETURNING *`
        )
            .bind(...values, id, payload.customerId)
            .first();

        return result ? c.json(result) : c.json({ error: "Not found" }, 404);
    });

    // Delete
    app.delete(`/${path}/:id`, async (c) => {
        const payload = c.get("jwtPayload");
        const id = c.req.param("id");

        await c.env.DB.prepare(`DELETE FROM ${table} WHERE id = ? AND customer_id = ?`)
            .bind(id, payload.customerId)
            .run();

        return c.json({ success: true });
    });
};

// Criando rotas CRUD para cada entidade
createCrudRoutes("customers", "customers", customerSchema);
createCrudRoutes("users", "users", userSchema);
createCrudRoutes("specialties", "specialties", specialtySchema);
createCrudRoutes("doctors", "doctors", doctorSchema);
createCrudRoutes("patients", "patients", patientSchema);
createCrudRoutes("appointments", "appointments", appointmentSchema);
createCrudRoutes("slots", "available_slots", slotSchema);

export default app;
