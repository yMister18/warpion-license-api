import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

// Pool de conexões seguro com o MySQL
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

/**
 * 1. VERIFICAR LICENÇA (Chamado pelo WarpionCore no Minecraft)
 */
export const verifyLicense = async (req: Request, res: Response): Promise<Response> => {
    const { key, ip, port } = req.body;

    if (!key || !ip || port === undefined) {
        return res.status(400).json({ status: "ERROR", message: "Parâmetros inválidos. Envie 'key', 'ip' e 'port'." });
    }

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

        // Procura correspondência de IP/Porta (com suporte a bypass de localhost)
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

        // Token JWT assinado
        const sessionToken = jwt.sign(
            { licenseKey: license.license_key, ip, port, modules: pluginsAllowed },
            process.env.JWT_SECRET as string,
            { expiresIn: '30m' }
        );

        return res.status(200).json({
            status: "SUCCESS",
            authorized: true,
            owner: license.owner_name,
            email: license.email,
            discord_id: license.discord_id,
            modules: pluginsAllowed,
            security: { session_token: sessionToken, checksum_required: true }
        });
    } catch (error) {
        console.error("Erro na verificação de licença:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno no servidor de autenticação." });
    }
};

/**
 * 2. ADICIONAR / ATUALIZAR SERVIDOR (Dashboard / Bot do Discord)
 */
export const addServerToLicense = async (req: Request, res: Response): Promise<Response> => {
    const { key, ip, port, plugins_allowed } = req.body;

    if (!key || !ip || port === undefined || !Array.isArray(plugins_allowed)) {
        return res.status(400).json({ status: "ERROR", message: "Parâmetros inválidos." });
    }

    try {
        const [licenses]: any = await pool.execute('SELECT id, status FROM licenses WHERE license_key = ?', [key]);
        if (!licenses || licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "A licença informada não existe no banco de dados." });
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

        return res.status(200).json({ status: "SUCCESS", message: `Servidor ${ip}:${port} vinculado/atualizado com sucesso.` });
    } catch (error) {
        console.error("Erro ao adicionar servidor:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno ao processar a requisição." });
    }
};

/**
 * 3. REMOVER SERVIDOR (Dashboard / Bot do Discord)
 */
export const removeServerFromLicense = async (req: Request, res: Response): Promise<Response> => {
    const { key, ip, port } = req.body;

    if (!key || !ip || port === undefined) {
        return res.status(400).json({ status: "ERROR", message: "Envie 'key', 'ip' e 'port' para remover." });
    }

    try {
        const [licenses]: any = await pool.execute('SELECT id FROM licenses WHERE license_key = ?', [key]);
        if (licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "Licença não encontrada." });
        }

        const [result]: any = await pool.execute(
            'DELETE FROM allowed_servers WHERE license_id = ? AND ip = ? AND port = ?',
            [licenses[0].id, ip, port]
        );

        if (result.affectedRows === 0) {
            return res.status(444).json({ status: "ERROR", message: "Este servidor não estava vinculado a esta licença." });
        }

        return res.status(200).json({ status: "SUCCESS", message: `Servidor ${ip}:${port} removido da licença com sucesso.` });
    } catch (error) {
        console.error("Erro ao remover servidor:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno no servidor." });
    }
};

/**
 * 4. CONSULTAR STATUS COMPLETO DA LICENÇA (Dashboard)
 */
export const getLicenseStatus = async (req: Request, res: Response): Promise<Response> => {
    const { key } = req.query; // Passado como Query Parameter (?key=WP-...)

    if (!key) {
        return res.status(400).json({ status: "ERROR", message: "Parâmetro 'key' obrigatório na URL." });
    }

    try {
        const [licenses]: any = await pool.execute('SELECT * FROM licenses WHERE license_key = ?', [key as string]);
        if (licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "Licença inválida." });
        }

        const license = licenses[0];
        const [servers]: any = await pool.execute('SELECT ip, port, plugins_json FROM allowed_servers WHERE license_id = ?', [license.id]);

        // Formata os servidores para devolver o array de plugins decodificado
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
        return res.status(500).json({ status: "ERROR", message: "Erro interno ao buscar dados." });
    }
};

/**
 * 5. GERAR NOVA LICENÇA MASTER (Apenas tu usas para criar chaves novas)
 */
export const createLicenseAdmin = async (req: Request, res: Response): Promise<Response> => {
    const { admin_secret, key, owner, email, discord_id } = req.body;

    // Proteção simples: exige que mandes o teu JWT_SECRET no corpo para provar que és o dono da API
    if (admin_secret !== process.env.JWT_SECRET) {
        return res.status(401).json({ status: "ERROR", message: "Não autorizado. Token secreto administrativo inválido." });
    }

    if (!key || !owner || !email || !discord_id) {
        return res.status(400).json({ status: "ERROR", message: "Faltam campos obrigatórios para criação." });
    }

    try {
        await pool.execute(
            'INSERT INTO licenses (license_key, owner_name, email, discord_id, status) VALUES (?, ?, ?, ?, ?)',
            [key, owner, email, discord_id, 'ACTIVE']
        );

        return res.status(201).json({ status: "SUCCESS", message: `Nova licença MASTER gerada com sucesso para ${owner}.` });
    } catch (error: any) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ status: "ERROR", message: "Esta chave de licença já existe no sistema." });
        }
        console.error("Erro ao criar licença master:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno ao gerar licença." });
    }
};