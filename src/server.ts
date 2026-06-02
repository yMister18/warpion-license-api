import express from 'express';
import dotenv from 'dotenv';
import { verifyLicense, addServerToLicense } from './controllers/LicenseController';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// 🟢 Rota que o JAR do Minecraft (WarpionCore) vai usar para validar
app.post('/v1/license/verify', verifyLicense);

// 🟢 Rota que a tua Dashboard / Bot do Discord vai usar para dar IPs ao cliente
app.post('/v1/license/add-server', addServerToLicense);

app.listen(port, () => {
    console.log(`🚀 API Warpion ativa e rodando com segurança na porta ${port}`);
});