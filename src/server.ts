import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { 
    verifyLicense, 
    addServerToLicense, 
    removeServerFromLicense, 
    getLicenseStatus, 
    createLicenseAdmin 
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
    max: 100, // Limita cada IP a 100 requisições por janela
    message: {
        status: "ERROR",
        message: "Muitas requisições vindas deste IP. Tente novamente mais tarde."
    },
    standardHeaders: true, // Retorna dados de limite nos headers HTTP
    legacyHeaders: false,
});

// Aplicar o limitador em todas as rotas da API
app.use('/v1/', apiLimiter);

// 🔌 Rota do Plugin (Minecraft)
app.post('/v1/license/verify', verifyLicense);

// 🖥️ Rotas de Gestão (Dashboard / Discord Bot / Bruno)
app.post('/v1/license/add-server', addServerToLicense);
app.delete('/v1/license/remove-server', removeServerFromLicense);
app.get('/v1/license/status', getLicenseStatus);

// 👑 Rota de Administração Suprema (Criar novas Chaves)
app.post('/v1/license/admin/create', createLicenseAdmin);

app.listen(port, () => {
    console.log(`🚀 [Warpion-API] Sistema Seguro e Completo ativo na porta ${port}`);
});