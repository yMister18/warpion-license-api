import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { z } from 'zod';
import crypto from 'crypto'; // 🔐 Biblioteca nativa do Node para criptografia de alto nível

dotenv.config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const VerifySchema = z.object({
    key: z.string().min(5),
    ip: z.string().refine((val) => {
        try {
            require('net').isIP(val);
            return true;
        } catch {
            return val === "0.0.0.0" || val === "127.0.0.1";
        }
    }).or(z.literal("0.0.0.0")).or(z.literal("127.0.0.1")),
    port: z.number().int().min(1).max(65535)
});

const AddServerSchema = z.object({
    key: z.string(),
    ip: z.string().refine((val) => {
        try {
            require('net').isIP(val);
            return true;
        } catch {
            return val === "0.0.0.0" || val === "127.0.0.1";
        }
    }).or(z.literal("0.0.0.0")).or(z.literal("127.0.0.1")),
    port: z.number().int().min(1).max(65535),
    plugins_allowed: z.array(z.string())
});

/**
 * 1. VERIFICAR LICENÇA COM ASSINATURA DIGITAL (Mecanismo Anti-Pirata)
 */
export const verifyLicense = async (req: Request, res: Response): Promise<Response> => {
    const parsed = VerifySchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ status: "ERROR", message: parsed.error.issues[0].message });
    }

    const { key, ip, port } = parsed.data;

    try {
        const [licenses]: any = await pool.execute('SELECT * FROM licenses WHERE license_key = ?', [key]);
        if (licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "Licença não encontrada no sistema." });
        }

        const license = licenses[0];
        if (license.status !== 'ACTIVE') {
            return res.status(403).json({ status: "ERROR", message: `Esta licença está atualmente: ${license.status}` });
        }

        const [servers]: any = await pool.execute('SELECT * FROM allowed_servers WHERE license_id = ?', [license.id]);

        const matchedServer = servers.find((srv: any) => {
            const isLocalhost = srv.ip === "0.0.0.0" || srv.ip === "127.0.0.1";
            const ipMatches = srv.ip === ip || (isLocalhost && (ip === "0.0.0.0" || ip === "127.0.0.1"));
            return ipMatches && srv.port === Number(port);
        });

        if (!matchedServer) {
            return res.status(403).json({ 
                status: "ERROR", 
                message: `Bloqueado: O endereço ${ip}:${port} não está autorizado para esta licença.` 
            });
        }

        const pluginsAllowed: string[] = JSON.parse(matchedServer.plugins_json);

        // Dados base da resposta
        const responseData = {
            status: "SUCCESS",
            authorized: true,
            owner: license.owner_name,
            modules: pluginsAllowed,
            timestamp: Date.now() // Timestamp dinâmico impede ataques de Replay (reutilizar respostas antigas)
        };

        // 🔐 GERAR CHECKSUM ANTI-ALTERAÇÃO (HMAC-SHA256)
        // Criamos uma assinatura baseada no conteúdo do JSON + a tua chave ultra secreta do .env
        const secret = process.env.JWT_SECRET as string;
        const jsonString = JSON.stringify(responseData);
        const checksum = crypto.createHmac('sha256', secret).update(jsonString).digest('hex');

        // Retorna os dados puros combinados com a assinatura de segurança no bloco final
        return res.status(200).json({
            ...responseData,
            security: {
                signature_checksum: checksum,
                checksum_required: true
            }
        });

    } catch (error) {
        console.error("Erro na verificação de licença:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno no servidor." });
    }
};

/**
 * 2. ADICIONAR / ATUALIZAR SERVIDOR
 */
export const addServerToLicense = async (req: Request, res: Response): Promise<Response> => {
    const parsed = AddServerSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ status: "ERROR", message: parsed.error.issues[0].message });
    }

    const { key, ip, port, plugins_allowed } = parsed.data;

    try {
        const [licenses]: any = await pool.execute('SELECT id, status FROM licenses WHERE license_key = ?', [key as string]);
        if (!licenses || licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "A licença informada não existe." });
        }

        if (licenses[0].status !== 'ACTIVE') {
            return res.status(403).json({ status: "ERROR", message: "Não é possível alterar uma licença inativa." });
        }

        const licenseId = licenses[0].id;
        const pluginsJsonString = JSON.stringify(plugins_allowed);

        await pool.execute(
            `INSERT INTO allowed_servers (license_id, ip, port, plugins_json) 
             VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE plugins_json = ?`,
            [licenseId, ip, port, pluginsJsonString, pluginsJsonString]
        );

        return res.status(200).json({ status: "SUCCESS", message: `Servidor ${ip}:${port} vinculado com sucesso.` });
    } catch (error) {
        console.error("Erro ao adicionar servidor:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno." });
    }
};

/**
 * 3. REMOVER SERVIDOR
 */
export const removeServerFromLicense = async (req: Request, res: Response): Promise<Response> => {
    const { key, ip, port } = req.body;
    if (!key || !ip || port === undefined) {
        return res.status(400).json({ status: "ERROR", message: "Envie 'key', 'ip' e 'port'." });
    }

    try {
        const [licenses]: any = await pool.execute('SELECT id FROM licenses WHERE license_key = ?', [key as string]);
        if (licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "Licença não encontrada." });
        }

        const [result]: any = await pool.execute(
            'DELETE FROM allowed_servers WHERE license_id = ? AND ip = ? AND port = ?',
            [licenses[0].id, ip, port]
        );

        if (result.affectedRows === 0) {
            return res.status(400).json({ status: "ERROR", message: "Este servidor não estava vinculado." });
        }

        return res.status(200).json({ status: "SUCCESS", message: `Servidor ${ip}:${port} removido.` });
    } catch (error) {
        console.error("Erro ao remover servidor:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno." });
    }
};

/**
 * 4. CONSULTAR STATUS DA LICENÇA
 */
export const getLicenseStatus = async (req: Request, res: Response): Promise<Response> => {
    const { key } = req.query;
    if (!key) {
        return res.status(400).json({ status: "ERROR", message: "Parâmetro 'key' obrigatório." });
    }

    try {
        const [licenses]: any = await pool.execute('SELECT * FROM licenses WHERE license_key = ?', [key as string]);
        if (licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "Licença inválida." });
        }

        const license = licenses[0];
        const [servers]: any = await pool.execute('SELECT ip, port, plugins_json FROM allowed_servers WHERE license_id = ?', [license.id]);

        const formattedServers = servers.map((srv: any) => ({
            ip: srv.ip,
            port: srv.port,
            plugins_allowed: JSON.parse(srv.plugins_json)
        }));

        return res.status(200).json({
            status: "SUCCESS",
            license_key: license.license_key,
            owner_name: license.owner_name,
            email: license.email,
            discord_id: license.discord_id,
            status_global: license.status,
            allowed_servers: formattedServers
        });
    } catch (error) {
        console.error("Erro ao consultar licença:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno." });
    }
};

/**
 * 5. GERAR NOVA LICENÇA MASTER
 */
export const createLicenseAdmin = async (req: Request, res: Response): Promise<Response> => {
    const { admin_secret, key, owner, email, discord_id } = req.body;

    if (admin_secret !== process.env.JWT_SECRET) {
        return res.status(401).json({ status: "ERROR", message: "Não autorizado." });
    }

    if (!key || !owner || !email || !discord_id) {
        return res.status(400).json({ status: "ERROR", message: "Faltam campos." });
    }

    try {
        await pool.execute(
            'INSERT INTO licenses (license_key, owner_name, email, discord_id, status) VALUES (?, ?, ?, ?, ?)',
            [key, owner, email, discord_id, 'ACTIVE']
        );
        return res.status(201).json({ status: "SUCCESS", message: `Licença criada para ${owner}.` });
    } catch (error: any) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ status: "ERROR", message: "Esta chave já existe." });
        }
        return res.status(500).json({ status: "ERROR", message: "Erro interno." });
    }
};

/**
 * 6. HEALTHCHECK
 */
export const healthCheck = async (req: Request, res: Response): Promise<Response> => {
    try {
        await pool.execute('SELECT 1');
        return res.status(200).json({ status: "UP", timestamp: new Date().toISOString(), database: "CONNECTED" });
    } catch (error) {
        return res.status(500).json({ status: "DOWN", timestamp: new Date().toISOString(), database: "DISCONNECTED" });
    }
};