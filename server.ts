import express, { Request, Response, NextFunction } from "express";
import path from "path";
import fs from "fs";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import {
  initDb,
  createLead,
  getLeads,
  getPortfolioProjects,
  createPortfolioProject,
  getApprovedTestimonials,
  createTestimonial,
  createClient,
  getClientByEmail,
  getClientById,
  getAllClients,
  updateClient,
  updateClientPassword,
  updateClientLastAccess,
  deleteClient,
  createClientWork,
  getClientWorks,
  getWorkById,
  getAllWorks,
  updateClientWork,
  deleteClientWork,
  getAllSiteAssets,
  getSiteAssetById,
  saveSiteAsset,
  resetSiteAsset,
  resetAllSiteAssets
} from "./src/db/queries.ts";
import { verifyPassword, generateToken, verifyToken, TokenPayload } from "./src/lib/auth.ts";

dotenv.config();

// Request type extension for authenticated client
interface AuthRequest extends Request {
  clientUser?: TokenPayload;
}

// Middleware: Authenticate Client
function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Acesso não autorizado. Faça login para continuar." });
  }

  const token = authHeader.substring(7);
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: "Sessão inválida ou expirada. Por favor, faça login novamente." });
  }

  req.clientUser = payload;
  next();
}

async function startServer() {
  // Inicializa tabelas e sementes
  await initDb();

  const app = express();
  const PORT = 3000;

  // Middleware de Segurança HTTP & Proteção
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
  });

  // Aumenta o limite de payload para suportar upload de fotos em alta resolução
  app.use(express.json({ limit: "30mb" }));
  app.use(express.urlencoded({ extended: true, limit: "30mb" }));

  // --- API ROUTES ---

  // Health Check
  app.get("/api/health", (req, res) => {
    res.json({
      status: "ok",
      database: "PostgreSQL Cloud SQL",
      timestamp: new Date().toISOString()
    });
  });

  // Download do arquivo ZIP para publicação no Netlify
  app.get(["/download-netlify-zip", "/site-zip", "/api/download-zip"], (req, res) => {
    const zipPath = path.resolve(process.cwd(), "public/site-brunodesigner-netlify.zip");
    if (fs.existsSync(zipPath)) {
      res.setHeader("Content-Disposition", 'attachment; filename="site-brunodesigner-netlify.zip"');
      res.setHeader("Content-Type", "application/zip");
      return res.sendFile(zipPath);
    }
    const distZipPath = path.resolve(process.cwd(), "dist/site-brunodesigner-netlify.zip");
    if (fs.existsSync(distZipPath)) {
      res.setHeader("Content-Disposition", 'attachment; filename="site-brunodesigner-netlify.zip"');
      res.setHeader("Content-Type", "application/zip");
      return res.sendFile(distZipPath);
    }
    return res.status(404).json({ error: "Arquivo zip ainda não gerado." });
  });

  // ==========================================
  // 1. AUTENTICAÇÃO DO CLIENTE (E-MAIL + SENHA)
  // ==========================================
  app.post("/api/auth/client-login", async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(400).json({ error: "E-mail e senha são obrigatórios." });
      }

      const client = await getClientByEmail(email);
      if (!client) {
        return res.status(401).json({ error: "E-mail ou senha incorretos." });
      }

      if (client.status === "inativo") {
        return res.status(403).json({ error: "Este cadastro está inativo. Entre em contato com o suporte." });
      }

      const isMatch = verifyPassword(password, client.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ error: "E-mail ou senha incorretos." });
      }

      // Atualiza data do último acesso
      await updateClientLastAccess(client.id);

      const tokenPayload: TokenPayload = {
        id: client.id,
        email: client.email,
        name: client.name,
        role: client.role || "cliente",
        status: client.status,
      };

      const token = generateToken(tokenPayload);

      res.json({
        success: true,
        message: `Bem-vindo(a), ${client.name}!`,
        token,
        client: {
          id: client.id,
          name: client.name,
          email: client.email,
          role: client.role,
          status: client.status,
          lastAccess: new Date().toISOString()
        }
      });
    } catch (error: any) {
      console.error("Erro no login do cliente:", error);
      res.status(500).json({ error: error.message || "Erro interno ao realizar login." });
    }
  });

  // ==========================================
  // 2. ÁREA PROTEGIDA DO CLIENTE (DASHBOARD & TRABALHOS)
  // ==========================================

  // Perfil do Cliente logado
  app.get("/api/client/me", authMiddleware, async (req: AuthRequest, res) => {
    try {
      const client = await getClientById(req.clientUser!.id);
      if (!client) {
        return res.status(404).json({ error: "Cliente não encontrado." });
      }
      res.json({
        client: {
          id: client.id,
          name: client.name,
          email: client.email,
          role: client.role,
          status: client.status,
          lastAccess: client.lastAccess
        }
      });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao buscar perfil." });
    }
  });

  // Trabalhos vinculados EXCLUSIVAMENTE ao cliente logado
  app.get("/api/client/works", authMiddleware, async (req: AuthRequest, res) => {
    try {
      const clientId = req.clientUser!.id;
      const works = await getClientWorks(clientId);

      // Tratamento de segurança: O link do drive só é liberado se status === 'disponivel'
      const sanitizedWorks = works.map((w) => {
        const isAvailable = w.status === "disponivel";
        return {
          id: w.id,
          title: w.title,
          description: w.description,
          workDate: w.workDate,
          status: w.status,
          availableAt: w.availableAt,
          expiresAt: w.expiresAt,
          createdAt: w.createdAt,
          // Link do Drive só enviado se disponível para acesso
          driveUrl: isAvailable ? w.driveUrl : null,
          hasDriveLink: Boolean(w.driveUrl)
        };
      });

      res.json({
        success: true,
        clientName: req.clientUser!.name,
        data: sanitizedWorks
      });
    } catch (error: any) {
      console.error("Erro ao buscar trabalhos do cliente:", error);
      res.status(500).json({ error: "Erro ao carregar seus trabalhos." });
    }
  });

  // Acesso direto e verificado ao Google Drive do trabalho
  app.get("/api/client/works/:id/access", authMiddleware, async (req: AuthRequest, res) => {
    try {
      const workId = parseInt(req.params.id, 10);
      const clientId = req.clientUser!.id;

      const work = await getWorkById(workId);
      if (!work) {
        return res.status(404).json({ error: "Trabalho não encontrado." });
      }

      // Verificação estrita de autorização do proprietário
      if (work.clientId !== clientId && req.clientUser!.role !== "admin") {
        return res.status(403).json({ error: "Você não tem permissão para acessar este trabalho." });
      }

      if (work.status !== "disponivel") {
        let msg = "Os arquivos deste trabalho ainda não estão liberados para download.";
        if (work.status === "em_producao") msg = "Seu trabalho está em produção.";
        if (work.status === "processando") msg = "Seus arquivos estão sendo preparados.";
        if (work.status === "expirado") msg = "O período de acesso a estes arquivos expirou.";
        if (work.status === "bloqueado") msg = "O acesso a estes arquivos está temporariamente bloqueado.";
        return res.status(400).json({ error: msg, status: work.status });
      }

      if (!work.driveUrl) {
        return res.status(404).json({ error: "Link do Google Drive ainda não foi cadastrado pelo administrador." });
      }

      res.json({
        success: true,
        driveUrl: work.driveUrl,
        title: work.title
      });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao validar acesso aos arquivos." });
    }
  });

  // ==========================================
  // 3. PAINEL ADMINISTRATIVO (GERENCIAMENTO DE CLIENTES & TRABALHOS)
  // ==========================================

  // Listar todos os clientes com seus trabalhos
  app.get("/api/admin/clients", async (req, res) => {
    try {
      const allClients = await getAllClients();
      const allWorks = await getAllWorks();

      const clientsWithWorks = allClients.map((client) => {
        const works = allWorks.filter((w) => w.clientId === client.id);
        return {
          id: client.id,
          name: client.name,
          email: client.email,
          status: client.status,
          role: client.role,
          lastAccess: client.lastAccess,
          createdAt: client.createdAt,
          updatedAt: client.updatedAt,
          worksCount: works.length,
          works: works
        };
      });

      res.json({ success: true, data: clientsWithWorks });
    } catch (error: any) {
      console.error("Erro ao listar clientes no admin:", error);
      res.status(500).json({ error: "Erro ao buscar clientes." });
    }
  });

  // Cadastrar novo cliente
  app.post("/api/admin/clients", async (req, res) => {
    try {
      const { name, email, password, status, role } = req.body;
      if (!name || !email || !password) {
        return res.status(400).json({ error: "Nome, e-mail e senha são obrigatórios para o cadastro." });
      }

      const client = await createClient({
        name,
        email,
        password,
        status: status || "ativo",
        role: role || "cliente"
      });

      res.status(201).json({
        success: true,
        message: "Cliente cadastrado com sucesso!",
        data: {
          id: client.id,
          name: client.name,
          email: client.email,
          status: client.status,
          role: client.role,
          createdAt: client.createdAt
        }
      });
    } catch (error: any) {
      console.error("Erro ao cadastrar cliente:", error);
      res.status(400).json({ error: error.message || "Erro ao cadastrar cliente." });
    }
  });

  // Atualizar cliente (dados / status)
  app.put("/api/admin/clients/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { name, email, status, role } = req.body;

      const updated = await updateClient(id, { name, email, status, role });
      if (!updated) {
        return res.status(404).json({ error: "Cliente não encontrado." });
      }

      res.json({ success: true, message: "Cliente atualizado com sucesso!", data: updated });
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Erro ao atualizar cliente." });
    }
  });

  // Redefinir senha do cliente
  app.put("/api/admin/clients/:id/password", async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { password } = req.body;
      if (!password || password.length < 4) {
        return res.status(400).json({ error: "A nova senha deve conter ao menos 4 caracteres." });
      }

      const updated = await updateClientPassword(id, password);
      if (!updated) {
        return res.status(404).json({ error: "Cliente não encontrado." });
      }

      res.json({ success: true, message: "Senha do cliente redefinida com sucesso!" });
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Erro ao redefinir senha." });
    }
  });

  // Excluir cliente
  app.delete("/api/admin/clients/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      await deleteClient(id);
      res.json({ success: true, message: "Cliente e seus trabalhos removidos com sucesso." });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao excluir cliente." });
    }
  });

  // Cadastrar novo trabalho para um cliente
  app.post("/api/admin/works", async (req, res) => {
    try {
      const { clientId, title, description, workDate, driveUrl, status, availableAt, expiresAt } = req.body;
      if (!clientId || !title) {
        return res.status(400).json({ error: "Cliente e título do trabalho são obrigatórios." });
      }

      const work = await createClientWork({
        clientId: Number(clientId),
        title,
        description,
        workDate,
        driveUrl,
        status: status || "disponivel",
        availableAt: availableAt ? new Date(availableAt) : undefined,
        expiresAt: expiresAt ? new Date(expiresAt) : undefined,
      });

      res.status(201).json({
        success: true,
        message: "Trabalho cadastrado e vinculado ao cliente com sucesso!",
        data: work
      });
    } catch (error: any) {
      console.error("Erro ao cadastrar trabalho:", error);
      res.status(500).json({ error: error.message || "Erro ao cadastrar trabalho." });
    }
  });

  // Atualizar trabalho do cliente
  app.put("/api/admin/works/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { title, description, workDate, driveUrl, status, availableAt, expiresAt } = req.body;

      const updated = await updateClientWork(id, {
        title,
        description,
        workDate,
        driveUrl,
        status,
        availableAt: availableAt ? new Date(availableAt) : (availableAt === null ? null : undefined),
        expiresAt: expiresAt ? new Date(expiresAt) : (expiresAt === null ? null : undefined),
      });

      if (!updated) {
        return res.status(404).json({ error: "Trabalho não encontrado." });
      }

      res.json({ success: true, message: "Trabalho atualizado com sucesso!", data: updated });
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Erro ao atualizar trabalho." });
    }
  });

  // Excluir trabalho
  app.delete("/api/admin/works/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      await deleteClientWork(id);
      res.json({ success: true, message: "Trabalho excluído com sucesso." });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao excluir trabalho." });
    }
  });

  // ==========================================
  // 4. LEADS, PORTFÓLIO E DEPOIMENTOS EXISTENTES
  // ==========================================

  // Receber Proposta / Orçamento / Lead
  app.post("/api/leads", async (req, res) => {
    try {
      const { name, email, phone, serviceType, projectBrief, estimatedBudget } = req.body;
      if (!name || !email || !serviceType) {
        return res.status(400).json({ error: "Nome, e-mail e tipo de serviço são obrigatórios." });
      }

      const lead = await createLead({
        name,
        email,
        phone,
        serviceType,
        projectBrief,
        estimatedBudget,
      });

      res.status(201).json({
        success: true,
        message: "Solicitação recebida com sucesso! Bruno entrará em contato em breve.",
        data: lead,
      });
    } catch (error: any) {
      console.error("Erro ao salvar lead:", error);
      res.status(500).json({ error: error.message || "Erro interno ao processar orçamento." });
    }
  });

  app.get("/api/leads", async (req, res) => {
    try {
      const leads = await getLeads();
      res.json({ data: leads });
    } catch (error: any) {
      console.error("Erro ao buscar leads:", error);
      res.status(500).json({ error: error.message || "Erro ao buscar contatos." });
    }
  });

  app.get("/api/portfolio", async (req, res) => {
    try {
      const projects = await getPortfolioProjects();
      res.json({ data: projects });
    } catch (error: any) {
      console.error("Erro ao buscar portfólio:", error);
      res.status(500).json({ error: error.message || "Erro ao carregar portfólio." });
    }
  });

  app.post("/api/portfolio", async (req, res) => {
    try {
      const project = await createPortfolioProject(req.body);
      res.status(201).json({ success: true, data: project });
    } catch (error: any) {
      console.error("Erro ao criar projeto:", error);
      res.status(500).json({ error: error.message || "Erro ao cadastrar projeto." });
    }
  });

  app.get("/api/testimonials", async (req, res) => {
    try {
      const testimonials = await getApprovedTestimonials();
      res.json({ data: testimonials });
    } catch (error: any) {
      console.error("Erro ao carregar depoimentos:", error);
      res.status(500).json({ error: error.message || "Erro ao carregar depoimentos." });
    }
  });

  app.post("/api/testimonials", async (req, res) => {
    try {
      const { authorName, companyOrRole, content, rating } = req.body;
      if (!authorName || !content) {
        return res.status(400).json({ error: "Nome e depoimento são obrigatórios." });
      }

      const testimonial = await createTestimonial({
        authorName,
        companyOrRole,
        content,
        rating: Number(rating) || 5,
      });

      res.status(201).json({
        success: true,
        message: "Depoimento enviado com sucesso!",
        data: testimonial,
      });
    } catch (error: any) {
      console.error("Erro ao registrar depoimento:", error);
      res.status(500).json({ error: error.message || "Erro ao registrar depoimento." });
    }
  });

  // ==========================================
  // 5. GESTÃO DE IMAGENS DO SITE (SITE ASSETS NO BANCO)
  // ==========================================

  // Listar todas as imagens salvas no banco de dados
  app.get("/api/assets", async (req, res) => {
    try {
      const assets = await getAllSiteAssets();
      res.json({ success: true, data: assets });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao buscar imagens do site." });
    }
  });

  // Salvar/Atualizar uma imagem no banco de dados (URLs e fotos enviadas)
  app.put("/api/assets/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { currentSrc, label, category, description, defaultPath } = req.body;
      if (!currentSrc) {
        return res.status(400).json({ error: "Endereço ou dados da imagem são obrigatórios." });
      }

      const saved = await saveSiteAsset({
        id,
        currentSrc,
        label: label || id,
        category: category || "geral",
        description: description || "",
        defaultPath: defaultPath || currentSrc,
      });

      res.json({
        success: true,
        message: "Imagem salva com sucesso no banco de dados!",
        data: saved,
      });
    } catch (error: any) {
      console.error("Erro ao salvar imagem no banco:", error);
      res.status(500).json({ error: "Erro interno ao salvar imagem no banco." });
    }
  });

  // Restaurar uma imagem para a foto padrão original
  app.post("/api/assets/reset/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const reset = await resetSiteAsset(id);
      res.json({ success: true, message: "Imagem restaurada para o padrão.", data: reset });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao restaurar imagem." });
    }
  });

  // Restaurar todas as imagens para os padrões originais
  app.post("/api/assets/reset-all", async (req, res) => {
    try {
      await resetAllSiteAssets();
      res.json({ success: true, message: "Todas as imagens foram restauradas com sucesso." });
    } catch (error: any) {
      res.status(500).json({ error: "Erro ao restaurar imagens." });
    }
  });

  // --- VITE MIDDLEWARE (SPA FALLBACK) ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Bruno Designer Server rodando na porta ${PORT}`);
  });
}

startServer();
