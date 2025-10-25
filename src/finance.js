import { Router } from 'express';
const router = Router();

// In-memory state (simple dev stub)
let currentBalance = 0;
let balanceHistory = [];

// GET current balance
router.get('/balance', (_req, res) => {
  const lastUpdate = balanceHistory.length > 0 ? balanceHistory[balanceHistory.length - 1].date : null;
  res.json({
    balance: currentBalance,
    amount: currentBalance, // backward compat
    currency: 'EUR',
    lastUpdate,
    updatedAt: lastUpdate,
    isLocked: true
  });
});

// GET balance history
router.get('/balance/history', (_req, res) => {
  res.json({ history: balanceHistory });
});

// POST configure balance
router.post('/balance/configure', (req, res) => {
  try {
    const { code, newBalance, reason } = req.body || {};
    const normalized = String(code ?? '').padStart(4, '0');
    if (normalized !== '0920') {
      return res.status(401).json({ message: 'Invalid security code' });
    }
    const parsed = parseFloat(newBalance);
    if (Number.isNaN(parsed)) {
      return res.status(400).json({ message: 'Invalid new balance' });
    }
    const old = currentBalance;
    currentBalance = parsed;
    const entry = {
      date: new Date().toISOString(),
      oldBalance: old,
      newBalance: currentBalance,
      reason: reason || 'Manual update'
    };
    balanceHistory.push(entry);
    // Keep last 100 entries
    if (balanceHistory.length > 100) balanceHistory = balanceHistory.slice(-100);
    return res.json({ newBalance: currentBalance, difference: currentBalance - old, entry });
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: String(err?.message || err) });
  }
});

// Stubs
router.get('/scheduled-operations', (_req, res) => res.json({ operations: [] }));
router.get('/transactions', (_req, res) => res.json({ transactions: [] }));

export default router;