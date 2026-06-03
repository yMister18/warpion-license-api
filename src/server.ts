import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { 
    verifyLicense, 
    addServerToLicense, 
    removeServerFromLicense, 
    getLicenseStatus, 
    createLicenseAdmin,
    healthCheck
} from './controllers/LicenseController';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// 🛡️ Middleware de Segurança e CORS
app.use(cors());
app.use(express.json());

// 🎛️ Configuração do Limitador de Acessos (Rate Limiter)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 150, // Aumentado ligeiramente para dar margem a múltiplos servidores ligando juntos
    message: {
        status: "ERROR",
        message: "Muitas requisições vindas deste IP. Tente novamente mais tarde."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// 🟢 Rota de Monitoramento Pública (Sem Rate Limit para não dar falso positivo em painéis)
app.get('/health', healthCheck);

// Aplicar o limitador nas rotas principais
app.use('/v1/', apiLimiter);

// 🔌 Rota do Plugin (Minecraft)
app.post('/v1/license/verify', verifyLicense);

// 🖥️ Rotas de Gestão (Dashboard / Discord Bot / Bruno)
app.post('/v1/license/add-server', addServerToLicense);
app.delete('/v1/license/remove-server', removeServerFromLicense);
app.get('/v1/license/status', getLicenseStatus);

// 👑 Rota de Administração Suprema (Criar novas Chaves)
app.post('/v1/license/admin/create', createLicenseAdmin);

// 🛑 CAPTURADOR GLOBAL DE ERROS (O seguro de vida da API)
// Se qualquer erro bizarro acontecer na API, este middleware impede o crash e responde com classe
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error("🚨 Erro Crítico Capturado:", err);
    
    return res.status(500).json({
        status: "ERROR",
        message: "Ocorreu um erro interno inesperado no servidor de licenças."
    });
});

app.listen(port, () => {
    console.log(`🚀 [Warpion-API] Sistema 100% Concluído e Blindado na porta ${port}`);
});