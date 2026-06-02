import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

// Criamos um pool de conexões com o teu MySQL da VPS
const pool = mysql.createPool({
    uri: process.env.MONGO_URI, // Usa a string do teu .env
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

export const verifyLicense = async (req: Request, res: Response): Promise<Response> => {
    const { key, ip, port } = req.body;

    // Validação básica de entrada para evitar requests malformados
    if (!key || !ip || port === undefined) {
        return res.status(400).json({ status: "ERROR", message: "Parâmetros inválidos. Envie 'key', 'ip' e 'port'." });
    }

    try {
        // 1. Procurar a licença ativa no banco de dados
        const [licenses]: any = await pool.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
            [key]
        );

        if (licenses.length === 0) {
            return res.status(404).json({ status: "ERROR", message: "Licença não encontrada no sistema." });
        }

        const license = licenses[0];

        // 2. Verificar o status da licença
        if (license.status !== 'ACTIVE') {
            return res.status(403).json({ status: "ERROR", message: `Esta licença está atualmente: ${license.status}` });
        }

        // 3. Buscar servidores autorizados para esta licença
        const [servers]: any = await pool.execute(
            'SELECT * FROM allowed_servers WHERE license_id = ?',
            [license.id]
        );

        // 4. Validar se o IP e Porta batem (Com suporte a bypass de localhost 0.0.0.0 ou 127.0.0.1)
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

        // Converter o campo TEXT do MySQL de volta para um Array do TypeScript
        const pluginsAllowed: string[] = JSON.parse(matchedServer.plugins_json);

        // 5. Geração de Token JWT robusto para blindar o Handshake
        const sessionToken = jwt.sign(
            { 
                licenseKey: license.license_key, 
                ip, 
                port, 
                modules: pluginsAllowed 
            },
            process.env.JWT_SECRET as string,
            { expiresIn: '30m' } // Expira em 30 minutos (bom para checagens periódicas)
        );

        // 6. Resposta de sucesso estruturada
        return res.status(200).json({
            status: "SUCCESS",
            authorized: true,
            owner: license.owner_name,
            email: license.email,
            discord_id: license.discord_id,
            modules: pluginsAllowed,
            security: {
                session_token: sessionToken,
                checksum_required: true
            }
        });

    } catch (error) {
        console.error("Erro na verificação de licença:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno no servidor de autenticação." });
    }
};

export const addServerToLicense = async (req: Request, res: Response): Promise<Response> => {
    const { key, ip, port, plugins_allowed } = req.body;

    // 1. Validação estrita dos campos recebidos
    if (!key || !ip || port === undefined || !Array.isArray(plugins_allowed)) {
        return res.status(400).json({ 
            status: "ERROR", 
            message: "Parâmetros inválidos. Envie 'key', 'ip', 'port' e um array 'plugins_allowed'." 
        });
    }

    try {
        // 2. Verifica se a licença realmente existe e está ativa
        const [licenses]: any = await pool.execute(
            'SELECT id, status FROM licenses WHERE license_key = ?',
            [key]
        );

        // CORREÇÃO: Validar estritamente se o resultado existe antes de tentar ler o 'id'
        if (!licenses || licenses.length === 0) {
            return res.status(404).json({ 
                status: "ERROR", 
                message: "A licença informada não existe no banco de dados. Crie a licença primeiro!" 
            });
        }

        if (licenses[0].status !== 'ACTIVE') {
            return res.status(403).json({ 
                status: "ERROR", 
                message: "Não é possível adicionar servidores a uma licença inativa." 
            });
        }

        const licenseId = licenses[0].id;
        const pluginsJsonString = JSON.stringify(plugins_allowed);

        // 3. Insere ou Atualiza (ON DUPLICATE KEY UPDATE) caso o IP:Porta já exista para esta licença
        // Isso evita erros se o cliente quiser apenas atualizar a lista de plugins permitidos no mesmo IP
        await pool.execute(
            `INSERT INTO allowed_servers (license_id, ip, port, plugins_json) 
             VALUES (?, ?, ?, ?) 
             ON DUPLICATE KEY UPDATE plugins_json = ?`,
            [licenseId, ip, port, pluginsJsonString, pluginsJsonString]
        );

        return res.status(200).json({
            status: "SUCCESS",
            message: `Servidor ${ip}:${port} vinculado com sucesso à licença.`
        });

    } catch (error) {
        console.error("Erro ao adicionar servidor à licença:", error);
        return res.status(500).json({ status: "ERROR", message: "Erro interno ao processar a requisição." });
    }
};