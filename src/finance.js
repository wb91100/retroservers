import { Router } from 'express';
const router = Router();

// In-memory state (simple dev stub for finance)
let currentBalance = 0;
let balanceHistory = [];
let transactions = [];
let scheduledOps = [];
let nextId = 1;

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

// -------- Transactions (in-memory) --------
router.get('/transactions', (_req, res) => {
  // Return newest first
  const list = [...transactions].sort((a, b) => new Date(b.date || b.createdAt) - new Date(a.date || a.createdAt));
  res.json({ transactions: list });
});

router.post('/transactions', (req, res) => {
  try {
    const { type, amount, description, category, date } = req.body || {};
    const normType = String(type || '').toUpperCase();
    if (!['CREDIT', 'DEBIT'].includes(normType)) return res.status(400).json({ message: 'Invalid type' });
    const value = parseFloat(amount);
    if (!Number.isFinite(value) || value <= 0) return res.status(400).json({ message: 'Invalid amount' });
    if (!description) return res.status(400).json({ message: 'Description required' });

    const tx = {
      id: String(nextId++),
      type: normType,
      amount: value,
      description: String(description),
      category: category || 'AUTRE',
      date: date ? new Date(date).toISOString() : new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
    transactions.unshift(tx);

    // Update balance
    currentBalance += normType === 'CREDIT' ? value : -value;

    return res.status(201).json({ transaction: tx, balance: currentBalance });
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: String(err?.message || err) });
  }
});

// -------- Scheduled operations (in-memory) --------
router.get('/scheduled-operations', (_req, res) => {
  const ops = [...scheduledOps].sort((a, b) => new Date(a.nextDate || 0) - new Date(b.nextDate || 0));
  res.json({ operations: ops });
});

router.post('/scheduled-operations', (req, res) => {
  try {
    const { type, amount, description, frequency, nextDate } = req.body || {};
    const normType = String(type || '').toUpperCase();
    if (!['SCHEDULED_PAYMENT', 'SCHEDULED_CREDIT'].includes(normType)) {
      return res.status(400).json({ message: 'Invalid scheduled operation type' });
    }
    const value = parseFloat(amount);
    if (!Number.isFinite(value) || value <= 0) return res.status(400).json({ message: 'Invalid amount' });
    if (!description) return res.status(400).json({ message: 'Description required' });
    const freq = String(frequency || 'MONTHLY').toUpperCase();
    if (!['MONTHLY', 'WEEKLY', 'QUARTERLY', 'YEARLY'].includes(freq)) {
      return res.status(400).json({ message: 'Invalid frequency' });
    }

    const op = {
      id: String(nextId++),
      type: normType,
      amount: value,
      description: String(description),
      frequency: freq,
      nextDate: nextDate ? new Date(nextDate).toISOString() : new Date().toISOString(),
      isActive: true,
      createdAt: new Date().toISOString()
    };
    scheduledOps.push(op);
    return res.status(201).json(op);
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: String(err?.message || err) });
  }
});

router.patch('/scheduled-operations/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { isActive, nextDate, description, amount, frequency, type } = req.body || {};
    const idx = scheduledOps.findIndex(op => String(op.id) === String(id));
    if (idx === -1) return res.status(404).json({ message: 'Operation not found' });
    const op = scheduledOps[idx];
    if (typeof isActive === 'boolean') op.isActive = isActive;
    if (nextDate !== undefined) op.nextDate = nextDate ? new Date(nextDate).toISOString() : op.nextDate;
    if (description !== undefined) op.description = String(description);
    if (amount !== undefined) {
      const val = parseFloat(amount);
      if (Number.isFinite(val) && val > 0) op.amount = val;
    }
    if (frequency !== undefined) {
      const f = String(frequency || '').toUpperCase();
      if (['MONTHLY', 'WEEKLY', 'QUARTERLY', 'YEARLY'].includes(f)) op.frequency = f;
    }
    if (type !== undefined) {
      const t = String(type || '').toUpperCase();
      if (['SCHEDULED_PAYMENT', 'SCHEDULED_CREDIT'].includes(t)) op.type = t;
    }
    scheduledOps[idx] = op;
    return res.json(op);
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: String(err?.message || err) });
  }
});

export default router;