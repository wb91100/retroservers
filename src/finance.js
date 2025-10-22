import { Router } from 'express';
const router = Router();

router.get('/balance', (req, res) => {
  res.json({ amount: 0, currency: 'EUR', updatedAt: new Date().toISOString() });
});

router.get('/balance/history', (req, res) => res.json([]));
router.get('/scheduled-operations', (req, res) => res.json([]));
router.get('/transactions', (req, res) => res.json([]));

export default router;