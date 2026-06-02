import express from 'express';
import dotenv from 'dotenv';
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

app.use(express.json());

// 🔌 Rota do Plugin (Minecraft)
app.post('/v1/license/verify', verifyLicense);

// 🖥️ Rotas de Gestão (Dashboard / Discord Bot / Bruno)
app.post('/v1/license/add-server', addServerToLicense);
app.delete('/v1/license/remove-server', removeServerFromLicense);
app.get('/v1/license/status', getLicenseStatus);

// 👑 Rota de Administração Suprema (Criar novas Chaves)
app.post('/v1/license/admin/create', createLicenseAdmin);

app.listen(port, () => {
    console.log(`🚀 [Warpion-API] Sistema de Licenciamento Completo ativo na porta ${port}`);
});