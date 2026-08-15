#![no_std]
#![allow(non_snake_case)]
/**
 * ================================================================================
 * مشروع: ميثاق Mithaq Protocol
 * الوصف: بروتوكول العقود الذكية الهجين للتجارة والعمل والائتمان على شبكة ستيلر
 * الإصدار: v6.5.4 - Mainnet Hardened + Security Fixes
 * الملف: contracts/src/main_contract.rs
 * المطور: فؤاد يحيى عزمان | Fuad Azman
 * البريد: fuad.mithaq@gmail.com | Pi: @Fuad207
 * الترخيص: © جميع الحقوق محفوظة 2026
 * ================================================================================
 * الميزات الأساسية:
 * 1. محرك السيولة الهجين HLE: 30% من الضمان يدخل مجمع السيولة
 * 2. نظام السمعة المتدرج: Diamond 95% LTV, Gold 75%, Silver 50%
 * 3. توزيع المصادرات: 50% منصة, 40% صندوق ضمان, 10% خزينة DAO
 * 4. الإفراج المتعدد: دفعات, مراحل, أقساط, تحرير تلقائي
 * 5. Anti Re-Entrancy + TTL موحد + معالجة غاز محسنة
 * 6. فصل توزيع الرسوم العادية عن المصادرات
 * 7. تفعيل المصادرات عند حل النزاعات
 * 8. إضافة قفل إعادة الدخول
 * 9. إكمال منطق القروض بالسمعة (LTV)
 * 10. دوال إدارية لتحديث المحافظ
 * 11. فحوصات دفاعية ضد القسمة على صفر
 * 12. مركزية توزيع الرسوم: يستدعي دالة `distribute_fees` من عقد الرمز
 * 13. تحديث نسبة استخدام مجمع السيولة بعد كل مساهمة (بدقة 0.01% - BPS)
 * 14. إزالة الأرقام السحرية: تعريف `MAX_MILESTONES` و`MAX_INSTALLMENTS`
 * 15. تحويل مباشر للأقساط من الدافع إلى المزود (بدون وسيط) -> تم التعديل لتحويل كامل القسط إلى العقد أولاً لأسباب أمنية
 * ================================================================================
 */

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, Env, String, Symbol, BytesN, Bytes, Map, Vec,
    token::{TokenClient},
    Val, TryIntoVal,
};

use crate::certificate::CertificateRegistryClient;
use crate::azman_token::AzmanTokenClient;

// ==================== 1. CONSTANTS ====================
const REVIEW_PERIOD_SECONDS: u64 = 259_200; // 3 days
const AUTO_RELEASE_SECONDS: u64 = 172_800;  // 2 days
const LEDGERS_IN_30_DAYS: u32 = 518_400;
const FEE_RECYCLE_DURATION: u64 = 604_800; // 7 days
const POOL_CONTRIBUTION_RATIO: i128 = 30;  // 30%

// TTL للقفل الداخلي (Instance Storage)
const INSTANCE_LIFETIME_THRESHOLD: u32 = 172_800;  // 2 days
const INSTANCE_BUMP_AMOUNT: u32 = 6_312_000;        // ~6 months

const REPUTATION: (i128, i128, i128, i128) = (-10, -5, -2, 2); // FRAUD, BREACH, NEGLECT, REWARD

const TIER: [(i128, i128); 3] = [(95, 95), (90, 75), (80, 50)]; // REP, LTV

// حدود استخدام مجمع السيولة (بالـ Basis Points - 0.01%)
const UTILIZATION_MIN_BPS: i128 = 2000;  // 20.00%
const UTILIZATION_MAX_BPS: i128 = 8000;  // 80.00%
const LIQUIDITY_SURCHARGE_PERCENT: i128 = 5;   // زيادة الرسوم عند انخفاض السيولة (نقاط مئوية)
const LIQUIDITY_DISCOUNT_PERCENT: i128 = 5;    // خصم عند ارتفاع السيولة (نقاط مئوية)

const FORFEITURE_SPLIT: (i128, i128, i128) = (50, 40, 10); // PLATFORM, RESERVE, DAO
const DEFAULT_GUARANTEE_ALLOC: i128 = 1; // 1% من رسوم المنصة يذهب لصندوق الضمان

// نسبة المصادرة من الرصيد عند العقوبات (%)
const FORFEITURE_FRAUD_PERCENT: i128 = 50;     // احتيال
const FORFEITURE_BREACH_PERCENT: i128 = 20;    // إخلال
const FORFEITURE_NEGLECT_PERCENT: i128 = 0;    // إهمال (لا مصادرة)

// حدود المراحل والأقساط (إزالة الأرقام السحرية)
const MAX_MILESTONES: u32 = 10;       // الحد الأقصى للمراحل في العقود الإنشائية
const MAX_INSTALLMENTS: u32 = 9;      // الحد الأقصى للأقساط في عقود الأقساط الدراسية

// Status Symbols
const S_PENDING: Symbol = symbol_short!("PEND");
const S_ACTIVE: Symbol = symbol_short!("ACTV");
const S_CANCEL: Symbol = symbol_short!("CANC");
const S_AWAIT: Symbol = symbol_short!("WAIT");
const S_COMPLET: Symbol = symbol_short!("COMP");
const S_AUTO: Symbol = symbol_short!("AUTO");
const S_DISPUTE: Symbol = symbol_short!("DISP");
const S_ARBITR: Symbol = symbol_short!("ARBT");
const S_OPEN: Symbol = symbol_short!("OPEN");

// Payment Status
const P_PENDING: Symbol = symbol_short!("PEND");
const P_COMPLET: Symbol = symbol_short!("COMP");
const P_CANCEL: Symbol = symbol_short!("CANC");

// Contract Types
const C_CONSTRUCT: Symbol = symbol_short!("CONS");
const C_TUITION: Symbol = symbol_short!("TUIT");
const C_REP_LEND: Symbol = symbol_short!("REPL");

// Penalty Types
const PEN_FRAUD: Symbol = symbol_short!("FRAU");
const PEN_BREACH: Symbol = symbol_short!("BREA");
const PEN_NEGLECT: Symbol = symbol_short!("NEGL");

// Reentrancy Lock Key
const LOCK_KEY: Symbol = symbol_short!("LOCK");

// ==================== 2. DATA TYPES ====================
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    ContractCounter, DisputeCounter,
    Commitment(u64), Dispute(u64), Reputation(Address),
    Admin, PiServer, AzmanToken, CertificateRegistry,
    LiquidityMetrics, FeeRecyclePool, TotalEscrowBalance,
    PlatformWallet, GuaranteeReserveWallet, DaoWallet,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    pub id: u64, pub creator: Address, pub counterparty: Address,
    pub original_value: i128, pub net_value: i128, pub down_payment: i128,
    pub first_release_amount: i128, pub second_release_amount: i128,
    pub contract_type: Symbol, pub status: Symbol,
    pub deadline: u64, pub accepted_at: u64, pub review_deadline: u64, pub auto_release_deadline: u64,
    pub first_release_done: bool, pub payment_status: Symbol, pub custom_step: u32,
    pub escrow_balance: i128, pub platform_fee_percent: i128, pub guarantee_reserve_alloc_percent: i128,
    pub legal_doc_hash: String, pub extra_data: Map<String, Val>, pub created_at: u64,
    pub contributes_to_pool: bool, pub liquidity_contribution: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dispute {
    pub id: u64, pub contract_id: u64, pub plaintiff: Address, pub defendant: Address,
    pub status: Symbol, pub penalty: Symbol, pub opened_at: u64, pub resolved_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiquidityPoolState {
    pub total_pooled: i128,
    pub total_recycled_fees: i128,
    pub active_contributors: u32,
    pub pool_utilization: i128, // نسبة الاستخدام بدقة 0.01% (BPS)
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentParams {
    pub original_value: i128, pub net_value: i128, pub down_payment: i128,
    pub contract_type: Symbol, pub deadline: u64, pub pi_payment_id: String,
    pub first_release_amount: i128, pub second_release_amount: i128, pub legal_doc_hash: String,
}

// ==================== 3. EVENTS ====================
#[contracttype] pub struct ContractCreated { pub id: u64, pub creator: Address, pub contract_type: Symbol, pub net_value: i128, pub down_payment: i128 }
#[contracttype] pub struct ContractAccepted { pub id: u64, pub counterparty: Address, pub escrowed_amount: i128 }
#[contracttype] pub struct ContractCancelled { pub id: u64, pub by: Address, pub refunded: i128 }
#[contracttype] pub struct PaymentUpdated { pub id: u64, pub status: Symbol }
#[contracttype] pub struct DeliveryConfirmed { pub id: u64, pub amount: i128, pub proof_hash: String }
#[contracttype] pub struct ContractCompleted { pub id: u64, pub final_payout: i128, pub fees_paid: i128 }
#[contracttype] pub struct AutoReleased { pub id: u64, pub payout: i128 }
#[contracttype] pub struct DisputeOpened { pub dispute_id: u64, pub contract_id: u64, pub by: Address, pub reason: String }
#[contracttype] pub struct DisputeResolved { pub dispute_id: u64, pub winner: Address, pub verdict: String, pub payout: i128 }
#[contracttype] pub struct MilestoneReleased { pub id: u64, pub milestone: u32, pub amount: i128 }
#[contracttype] pub struct InstallmentPaid { pub id: u64, pub installment: u32, pub amount: i128 }
#[contracttype] pub struct LiquidityContributed { pub contract_id: u64, pub amount: i128, pub total_pooled: i128 }
#[contracttype] pub struct LiquidityWithdrawn { pub contract_id: u64, pub amount: i128, pub total_pooled: i128 }
#[contracttype] pub struct FeesRecycled { pub amount: i128, pub recycle_end: u64 }
#[contracttype] pub struct PoolRebalanced { pub old_utilization: i128, pub new_utilization: i128, pub fee_adjustment: i128 }
#[contracttype] pub struct FeesDistributed { pub total: i128, pub platform: i128, pub reserve: i128, pub dao: i128 }

// ==================== 4. CONTRACT ====================
#[contract]
pub struct MithaqContract;

#[contractimpl]
impl MithaqContract {
    // ===== INTERNAL HELPERS =====
    fn _extend_ttl(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(key, LEDGERS_IN_30_DAYS, LEDGERS_IN_30_DAYS);
    }

    fn _get_reputation(env: &Env, user: &Address) -> i128 {
        let key = DataKey::Reputation(user.clone());
        let rep = env.storage().persistent().get(&key).unwrap_or(0);
        Self::_extend_ttl(env, &key);
        rep
    }

    fn _add_reputation(env: &Env, user: &Address, points: i128) {
        let new_rep = (Self::_get_reputation(env, user) + points).max(0);
        let key = DataKey::Reputation(user.clone());
        env.storage().persistent().set(&key, &new_rep);
        Self::_extend_ttl(env, &key);
    }

    fn _get_commitment(env: &Env, id: u64) -> Commitment {
        let key = DataKey::Commitment(id);
        let c: Commitment = env.storage().persistent().get(&key).expect("Commitment not found");
        Self::_extend_ttl(env, &key);
        c
    }

    fn _save_commitment(env: &Env, id: u64, c: &Commitment) {
        let key = DataKey::Commitment(id);
        env.storage().persistent().set(&key, c);
        Self::_extend_ttl(env, &key);
    }

    fn _transfer(env: &Env, token: &Address, to: &Address, amount: i128) {
        if amount <= 0 { return; }
        env.authorize_as_current_contract(Vec::new(env));
        TokenClient::new(env, token).transfer(&env.current_contract_address(), to, &amount);
    }

    fn _get_liquidity_pool(env: &Env) -> LiquidityPoolState {
        let key = DataKey::LiquidityMetrics;
        let state = env.storage().persistent().get(&key).unwrap_or(LiquidityPoolState {
            total_pooled: 0,
            total_recycled_fees: 0,
            active_contributors: 0,
            pool_utilization: 5000, // 50.00% (BPS)
            last_updated: env.ledger().timestamp(),
        });
        Self::_extend_ttl(env, &key);
        state
    }

    fn _set_liquidity_pool(env: &Env, state: &LiquidityPoolState) {
        let key = DataKey::LiquidityMetrics;
        env.storage().persistent().set(&key, state);
        Self::_extend_ttl(env, &key);
    }

    fn _get_total_escrow(env: &Env) -> i128 {
        let key = DataKey::TotalEscrowBalance;
        let total = env.storage().persistent().get(&key).unwrap_or(0);
        Self::_extend_ttl(env, &key);
        total
    }

    fn _set_total_escrow(env: &Env, amount: i128) {
        let key = DataKey::TotalEscrowBalance;
        env.storage().persistent().set(&key, &amount);
        Self::_extend_ttl(env, &key);
    }

    // توزيع الرسوم العادية: يستدعي دالة `distribute_fees` من عقد الرمز
    // payer دائماً هو العقد الحالي لضمان الأمان
    fn _call_distribute_fees(env: &Env, fees: i128, guarantee_alloc_percent: i128) {
        if fees <= 0 { return; }
        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();
        env.authorize_as_current_contract(Vec::new(env));
        let token_client = AzmanTokenClient::new(env, &token);
        token_client.distribute_fees(
            &env.current_contract_address(),
            &env.current_contract_address(), // payer = العقد نفسه
            fees,
            guarantee_alloc_percent,
        );
    }

    // توزيع المصادرات 50/40/10 (منصة/صندوق/DAO)
    fn _distribute_forfeiture(env: &Env, amount: i128) {
        if amount <= 0 { return; }
        let platform_share = (amount * FORFEITURE_SPLIT.0) / 100;
        let reserve_share = (amount * FORFEITURE_SPLIT.1) / 100;
        let dao_share = amount - platform_share - reserve_share;

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();
        let platform_wallet = env.storage().persistent().get::<_, Address>(&DataKey::PlatformWallet).unwrap();
        let reserve_wallet = env.storage().persistent().get::<_, Address>(&DataKey::GuaranteeReserveWallet).unwrap();
        let dao_wallet = env.storage().persistent().get::<_, Address>(&DataKey::DaoWallet).unwrap();

        if platform_share > 0 {
            Self::_transfer(env, &token, &platform_wallet, platform_share);
        }
        if reserve_share > 0 {
            Self::_transfer(env, &token, &reserve_wallet, reserve_share);
        }
        if dao_share > 0 {
            Self::_transfer(env, &token, &dao_wallet, dao_share);
        }

        env.events().publish((symbol_short!("forfeit_dist"),), FeesDistributed {
            total: amount,
            platform: platform_share,
            reserve: reserve_share,
            dao: dao_share,
        });
    }

    fn _issue_cert(env: &Env, c: &Commitment, imprint: &str) {
        let cert_id = env.crypto().sha256(&Bytes::from_slice(env, &c.id.to_be_bytes()));
        let registry = env.storage().persistent().get::<_, Address>(&DataKey::CertificateRegistry).unwrap();
        env.authorize_as_current_contract(Vec::new(env));
        CertificateRegistryClient::new(env, &registry).issue_certificate(
            &env.current_contract_address(),
            &cert_id.to_bytes(),
            &c.creator,
            &c.counterparty,
            &String::from_str(env, imprint),
        );
    }

    // دالة حساب الرسوم الديناميكية (تشمل السمعة والسيولة)
    fn _calculate_platform_fee_percent(env: &Env, creator: &Address) -> i128 {
        let rep = Self::_get_reputation(env, creator);
        let mut fee = 2i128; // 2%
        if rep >= 100 {
            fee = 1;
        } else if rep < 20 {
            fee = 4;
        }

        let pool = Self::_get_liquidity_pool(env);
        if pool.pool_utilization < UTILIZATION_MIN_BPS {
            fee += LIQUIDITY_SURCHARGE_PERCENT;
        } else if pool.pool_utilization > UTILIZATION_MAX_BPS {
            fee = (fee - LIQUIDITY_DISCOUNT_PERCENT).max(0);
        }
        fee
    }

    // ===== REENTRANCY GUARD =====
    fn _lock(env: &Env) {
        let locked: bool = env.storage().instance().get(&LOCK_KEY).unwrap_or(false);
        if locked {
            panic!("Reentrancy detected");
        }
        env.storage().instance().set(&LOCK_KEY, &true);
        env.storage().instance().extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn _unlock(env: &Env) {
        env.storage().instance().set(&LOCK_KEY, &false);
        env.storage().instance().extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    // ===== PUBLIC FUNCTIONS =====
    pub fn initialize(
        env: Env,
        admin: Address,
        pi_server: Address,
        azman_token: Address,
        cert_registry: Address,
        platform: Address,
        reserve: Address,
        dao: Address,
    ) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        admin.require_auth();

        let keys = [
            DataKey::Admin,
            DataKey::PiServer,
            DataKey::AzmanToken,
            DataKey::CertificateRegistry,
            DataKey::PlatformWallet,
            DataKey::GuaranteeReserveWallet,
            DataKey::DaoWallet,
        ];
        let values: [Val; 7] = [
            admin.to_val(),
            pi_server.to_val(),
            azman_token.to_val(),
            cert_registry.to_val(),
            platform.to_val(),
            reserve.to_val(),
            dao.to_val(),
        ];
        for (key, val) in keys.iter().zip(values.iter()) {
            env.storage().persistent().set(key, val);
            Self::_extend_ttl(&env, key);
        }

        let counter_key = DataKey::ContractCounter;
        env.storage().persistent().set(&counter_key, &0u64);
        Self::_extend_ttl(&env, &counter_key);

        let dispute_key = DataKey::DisputeCounter;
        env.storage().persistent().set(&dispute_key, &0u64);
        Self::_extend_ttl(&env, &dispute_key);

        let escrow_key = DataKey::TotalEscrowBalance;
        env.storage().persistent().set(&escrow_key, &0i128);
        Self::_extend_ttl(&env, &escrow_key);

        let pool = LiquidityPoolState {
            total_pooled: 0,
            total_recycled_fees: 0,
            active_contributors: 0,
            pool_utilization: 5000,
            last_updated: env.ledger().timestamp(),
        };
        Self::_set_liquidity_pool(&env, &pool);

        env.storage().instance().set(&LOCK_KEY, &false);
    }

    pub fn create_commitment(
        env: Env,
        creator: Address,
        counterparty: Address,
        params: CommitmentParams,
    ) -> u64 {
        Self::_lock(&env);
        env.storage().persistent().get::<_, Address>(&DataKey::PiServer)
            .expect("PiServer not set")
            .require_auth();

        if params.net_value <= 0 { panic!("Net value must be positive"); }
        if params.down_payment < 0 || params.down_payment > params.net_value { panic!("Invalid down payment"); }
        if creator == counterparty { panic!("Self-dealing prohibited"); }
        if params.first_release_amount + params.second_release_amount != params.net_value {
            panic!("Release amounts must sum to net value");
        }
        if params.first_release_amount > params.down_payment {
            panic!("First release cannot exceed down payment");
        }
        if params.deadline <= env.ledger().timestamp() { panic!("Deadline must be in future"); }

        if params.contract_type == C_REP_LEND {
            if params.net_value == 0 {
                panic!("Net value cannot be zero");
            }
            let rep = Self::_get_reputation(&env, &creator);
            let mut max_ltv = 0i128;
            if rep >= TIER[0].0 {
                max_ltv = TIER[0].1;
            } else if rep >= TIER[1].0 {
                max_ltv = TIER[1].1;
            } else if rep >= TIER[2].0 {
                max_ltv = TIER[2].1;
            } else {
                panic!("Credit rejected: Reputation below 80");
            }

            let loan_amount = params.net_value - params.down_payment;
            let requested_ltv = (loan_amount * 100) / params.net_value;
            if requested_ltv > max_ltv {
                panic!("Credit rejected: LTV exceeds allowed limit");
            }
        }

        let id = env.storage().persistent().get::<_, u64>(&DataKey::ContractCounter).unwrap_or(0) + 1;
        env.storage().persistent().set(&DataKey::ContractCounter, &id);
        Self::_extend_ttl(&env, &DataKey::ContractCounter);

        let platform_fee = Self::_calculate_platform_fee_percent(&env, &creator);

        let c = Commitment {
            id,
            creator,
            counterparty,
            original_value: params.original_value,
            net_value: params.net_value,
            down_payment: params.down_payment,
            first_release_amount: params.first_release_amount,
            second_release_amount: params.second_release_amount,
            contract_type: params.contract_type,
            status: S_PENDING,
            deadline: params.deadline,
            accepted_at: 0,
            review_deadline: 0,
            auto_release_deadline: 0,
            first_release_done: false,
            payment_status: P_PENDING,
            custom_step: 0,
            escrow_balance: 0,
            platform_fee_percent: platform_fee,
            guarantee_reserve_alloc_percent: DEFAULT_GUARANTEE_ALLOC,
            legal_doc_hash: params.legal_doc_hash,
            extra_data: Map::new(&env),
            created_at: env.ledger().timestamp(),
            contributes_to_pool: false,
            liquidity_contribution: 0,
        };
        Self::_save_commitment(&env, id, &c);

        env.events().publish((symbol_short!("created"),), ContractCreated {
            id,
            creator: c.creator,
            contract_type: c.contract_type,
            net_value: c.net_value,
            down_payment: c.down_payment,
        });

        Self::_unlock(&env);
        id
    }

    pub fn accept(env: Env, id: u64, funder: Address, doc_hash: String) {
        Self::_lock(&env);
        funder.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        if c.status != S_PENDING || env.ledger().timestamp() > c.deadline { panic!("Invalid state"); }
        if c.legal_doc_hash != doc_hash || funder != c.counterparty { panic!("Auth failed"); }

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();
        TokenClient::new(&env, &token).transfer(&funder, &env.current_contract_address(), &c.down_payment);

        c.escrow_balance = c.down_payment;
        c.status = S_ACTIVE;
        c.accepted_at = env.ledger().timestamp();

        Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) + c.escrow_balance);

        let contribution = (c.down_payment * POOL_CONTRIBUTION_RATIO) / 100;
        if contribution > 0 {
            c.contributes_to_pool = true;
            c.liquidity_contribution = contribution;
            let mut pool = Self::_get_liquidity_pool(&env);
            pool.total_pooled += contribution;
            pool.active_contributors += 1;

            let total_escrow = Self::_get_total_escrow(&env);
            if total_escrow > 0 {
                pool.pool_utilization = (pool.total_pooled * 10000) / total_escrow;
            } else {
                pool.pool_utilization = 0;
            }
            pool.last_updated = env.ledger().timestamp();

            Self::_set_liquidity_pool(&env, &pool);
        }

        Self::_save_commitment(&env, id, &c);

        env.events().publish((symbol_short!("accepted"),), ContractAccepted {
            id,
            counterparty: c.counterparty,
            escrowed_amount: c.down_payment,
        });

        Self::_unlock(&env);
    }

    pub fn cancel_commitment(env: Env, id: u64, caller: Address, reason: Symbol) {
        Self::_lock(&env);
        caller.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        let c_force_maj = symbol_short!("FORCE_MAJ");
        let c_mutual = symbol_short!("MUTUAL");

        if c.status != S_PENDING && reason != c_mutual && reason != c_force_maj {
            panic!("Active contracts require mutual consent or force majeure");
        }
        if caller != c.creator && caller != c.counterparty { panic!("Not a party"); }

        c.status = S_CANCEL;
        let refunded = c.escrow_balance;

        if c.contributes_to_pool {
            let mut pool = Self::_get_liquidity_pool(&env);
            pool.total_pooled = (pool.total_pooled - c.liquidity_contribution).max(0);
            pool.active_contributors = pool.active_contributors.saturating_sub(1);

            let total_escrow = Self::_get_total_escrow(&env);
            pool.pool_utilization = if total_escrow > 0 {
                (pool.total_pooled * 10000) / total_escrow
            } else {
                0
            };
            pool.last_updated = env.ledger().timestamp();
            Self::_set_liquidity_pool(&env, &pool);
            c.contributes_to_pool = false;
            c.liquidity_contribution = 0;
        }

        if refunded > 0 {
            let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();
            Self::_transfer(&env, &token, &c.counterparty, refunded);
            c.escrow_balance = 0;
            Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) - refunded);
        }

        Self::_save_commitment(&env, id, &c);

        env.events().publish((symbol_short!("cancelled"),), ContractCancelled {
            id,
            by: caller,
            refunded,
        });

        Self::_unlock(&env);
    }

    pub fn update_payment_status(env: Env, id: u64, payment_status: Symbol) {
        Self::_lock(&env);
        env.storage().persistent().get::<_, Address>(&DataKey::PiServer)
            .expect("PiServer not set")
            .require_auth();
        let mut c = Self::_get_commitment(&env, id);
        c.payment_status = payment_status.clone();
        if payment_status == P_CANCEL {
            c.status = S_CANCEL;
        }
        Self::_save_commitment(&env, id, &c);
        env.events().publish((symbol_short!("pay_update"),), PaymentUpdated { id, status: payment_status });
        Self::_unlock(&env);
    }

    pub fn confirm_delivery(env: Env, id: u64, counterparty: Address, proof: String) {
        Self::_lock(&env);
        counterparty.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        if counterparty != c.counterparty || c.status != S_ACTIVE || c.first_release_done { panic!("Invalid"); }

        let amount = c.first_release_amount;
        if amount > c.escrow_balance { panic!("Insufficient escrow balance"); }

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();
        Self::_transfer(&env, &token, &c.creator, amount);

        c.escrow_balance -= amount;
        Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) - amount);

        c.first_release_done = true;
        c.status = S_AWAIT;
        c.review_deadline = env.ledger().timestamp() + REVIEW_PERIOD_SECONDS;
        c.auto_release_deadline = c.review_deadline + AUTO_RELEASE_SECONDS;
        c.extra_data.set(String::from_str(&env, "proof"), proof.to_val());

        Self::_save_commitment(&env, id, &c);

        env.events().publish((symbol_short!("delivered"),), DeliveryConfirmed {
            id,
            amount,
            proof_hash: proof,
        });

        Self::_unlock(&env);
    }

    pub fn confirm_review(env: Env, id: u64, counterparty: Address) {
        Self::_lock(&env);
        counterparty.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        if counterparty != c.counterparty || c.status != S_AWAIT { panic!("Invalid"); }

        let balance = c.escrow_balance;
        let fees = (balance * c.platform_fee_percent) / 100;
        let payout = balance - fees;

        c.escrow_balance = 0;
        c.status = S_COMPLET;

        Self::_add_reputation(&env, &c.creator, REPUTATION.3);
        Self::_add_reputation(&env, &c.counterparty, REPUTATION.3);

        Self::_save_commitment(&env, id, &c);

        Self::_issue_cert(&env, &c, "Mithaq Verified");

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();

        Self::_call_distribute_fees(&env, fees, c.guarantee_reserve_alloc_percent);
        Self::_transfer(&env, &token, &c.creator, payout);

        Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) - balance);

        env.events().publish((symbol_short!("completed"),), ContractCompleted {
            id,
            final_payout: payout,
            fees_paid: fees,
        });

        Self::_unlock(&env);
    }

    pub fn auto_release(env: Env, id: u64) {
        Self::_lock(&env);
        let mut c = Self::_get_commitment(&env, id);

        if c.status != S_AWAIT || env.ledger().timestamp() < c.auto_release_deadline { panic!("Not ready"); }

        let balance = c.escrow_balance;
        let fees = (balance * c.platform_fee_percent) / 100;
        let payout = balance - fees;

        c.escrow_balance = 0;
        c.status = S_AUTO;

        Self::_add_reputation(&env, &c.counterparty, REPUTATION.2);
        Self::_add_reputation(&env, &c.creator, REPUTATION.3);

        Self::_save_commitment(&env, id, &c);

        Self::_issue_cert(&env, &c, "Mithaq Auto-Verified");

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();

        Self::_call_distribute_fees(&env, fees, c.guarantee_reserve_alloc_percent);
        Self::_transfer(&env, &token, &c.creator, payout);

        Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) - balance);

        env.events().publish((symbol_short!("auto_rel"),), AutoReleased { id, payout });

        Self::_unlock(&env);
    }

    pub fn open_dispute(env: Env, id: u64, caller: Address, reason: String) -> u64 {
        Self::_lock(&env);
        caller.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        if caller != c.creator && caller != c.counterparty { panic!("Locus standi required"); }
        if c.status != S_AWAIT && c.status != S_ACTIVE { panic!("Ineligible state"); }

        c.status = S_DISPUTE;
        Self::_save_commitment(&env, id, &c);

        let dispute_id = env.storage().persistent().get::<_, u64>(&DataKey::DisputeCounter).unwrap_or(0) + 1;
        env.storage().persistent().set(&DataKey::DisputeCounter, &dispute_id);
        Self::_extend_ttl(&env, &DataKey::DisputeCounter);

        let dispute = Dispute {
            id: dispute_id,
            contract_id: id,
            plaintiff: caller.clone(),
            defendant: if caller == c.creator { c.counterparty.clone() } else { c.creator.clone() },
            status: S_OPEN,
            penalty: symbol_short!("PENDING"),
            opened_at: env.ledger().timestamp(),
            resolved_at: 0,
        };
        env.storage().persistent().set(&DataKey::Dispute(dispute_id), &dispute);
        Self::_extend_ttl(&env, &DataKey::Dispute(dispute_id));

        env.events().publish((symbol_short!("dispute_open"),), DisputeOpened {
            dispute_id,
            contract_id: id,
            by: caller,
            reason,
        });

        Self::_unlock(&env);
        dispute_id
    }

    pub fn resolve_dispute(
        env: Env,
        dispute_id: u64,
        winner: Address,
        verdict_text: String,
        penalty_type: Symbol,
    ) {
        Self::_lock(&env);
        env.storage().persistent().get::<_, Address>(&DataKey::Admin)
            .expect("Admin not set")
            .require_auth();

        let mut d: Dispute = env.storage().persistent().get(&DataKey::Dispute(dispute_id))
            .expect("Dispute not found");
        if d.status != S_OPEN { panic!("Case closed"); }

        let mut c = Self::_get_commitment(&env, d.contract_id);

        if winner != c.creator && winner != c.counterparty {
            panic!("Winner must be a party");
        }

        let penalty_points = if penalty_type == PEN_FRAUD {
            REPUTATION.0
        } else if penalty_type == PEN_BREACH {
            REPUTATION.1
        } else {
            REPUTATION.2
        };

        let loser = if winner == c.creator { c.counterparty.clone() } else { c.creator.clone() };
        Self::_add_reputation(&env, &loser, penalty_points);
        Self::_add_reputation(&env, &winner, REPUTATION.3);

        d.status = S_ARBITR;
        d.penalty = penalty_type.clone();
        d.resolved_at = env.ledger().timestamp();
        c.status = S_COMPLET;

        let balance = c.escrow_balance;

        let forfeiture_percent = if penalty_type == PEN_FRAUD {
            FORFEITURE_FRAUD_PERCENT
        } else if penalty_type == PEN_BREACH {
            FORFEITURE_BREACH_PERCENT
        } else {
            FORFEITURE_NEGLECT_PERCENT
        };

        let forfeiture_amount = (balance * forfeiture_percent) / 100;
        let remaining_balance = balance - forfeiture_amount;
        let fees = (remaining_balance * c.platform_fee_percent) / 100;
        let payout = remaining_balance - fees;

        c.escrow_balance = 0;
        env.storage().persistent().set(&DataKey::Dispute(dispute_id), &d);
        Self::_save_commitment(&env, d.contract_id, &c);

        Self::_issue_cert(&env, &c, "Mithaq Dispute-Resolved");

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();

        if forfeiture_amount > 0 {
            Self::_distribute_forfeiture(&env, forfeiture_amount);
        }

        Self::_call_distribute_fees(&env, fees, c.guarantee_reserve_alloc_percent);
        Self::_transfer(&env, &token, &winner, payout);

        Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) - balance);

        env.events().publish((symbol_short!("dispute_res"),), DisputeResolved {
            dispute_id,
            winner,
            verdict: verdict_text,
            payout,
        });

        Self::_unlock(&env);
    }

    pub fn release_milestone(env: Env, id: u64, caller: Address, milestone: u32) {
        Self::_lock(&env);
        caller.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        if c.contract_type != C_CONSTRUCT { panic!("Not construction"); }
        if caller != c.counterparty { panic!("Only counterparty"); }
        if c.status != S_ACTIVE && c.status != S_AWAIT { panic!("Contract frozen or complete"); }
        if milestone > MAX_MILESTONES { panic!("Milestone out of range"); }

        let current_milestone: u32 = c.extra_data
            .get(String::from_str(&env, "milestone"))
            .unwrap_or(Val::from_u32(0).into())
            .try_into_val(&env)
            .unwrap_or(0u32);
        if milestone <= current_milestone { panic!("Double spending"); }

        c.extra_data.set(String::from_str(&env, "milestone"), Val::from_u32(milestone).into());

        let amount_per_milestone = c.down_payment / MAX_MILESTONES as i128;
        let milestone_fee = (amount_per_milestone * c.platform_fee_percent) / 100;
        let net_amount = amount_per_milestone - milestone_fee;

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();

        Self::_call_distribute_fees(&env, milestone_fee, c.guarantee_reserve_alloc_percent);
        Self::_transfer(&env, &token, &c.creator, net_amount);

        c.escrow_balance -= amount_per_milestone;
        Self::_set_total_escrow(&env, Self::_get_total_escrow(&env) - amount_per_milestone);

        if milestone >= MAX_MILESTONES {
            c.status = S_COMPLET;
            Self::_add_reputation(&env, &c.creator, REPUTATION.3);
            Self::_add_reputation(&env, &c.counterparty, REPUTATION.3);
        }

        Self::_save_commitment(&env, id, &c);
        env.events().publish((symbol_short!("milestone"),), MilestoneReleased {
            id,
            milestone,
            amount: net_amount,
        });

        Self::_unlock(&env);
    }

    pub fn pay_installment(env: Env, id: u64, caller: Address, installment_num: u32) {
        Self::_lock(&env);
        caller.require_auth();
        let mut c = Self::_get_commitment(&env, id);

        if c.contract_type != C_TUITION { panic!("Not tuition"); }
        if caller != c.counterparty { panic!("Unauthorized payer"); }
        if c.status != S_ACTIVE { panic!("Account not in good standing"); }
        if installment_num > MAX_INSTALLMENTS { panic!("Installment out of range"); }

        let current_installment: u32 = c.extra_data
            .get(String::from_str(&env, "installment"))
            .unwrap_or(Val::from_u32(0).into())
            .try_into_val(&env)
            .unwrap_or(0u32);
        if installment_num <= current_installment { panic!("Installment previously cleared"); }

        c.extra_data.set(String::from_str(&env, "installment"), Val::from_u32(installment_num).into());

        let amount_per_installment = c.down_payment / MAX_INSTALLMENTS as i128;
        let installment_fee = (amount_per_installment * c.platform_fee_percent) / 100;
        let net_amount = amount_per_installment - installment_fee;

        let token = env.storage().persistent().get::<_, Address>(&DataKey::AzmanToken).unwrap();

        // 1. تحويل كامل القسط من الدافع إلى العقد (أمان)
        TokenClient::new(&env, &token).transfer(&caller, &env.current_contract_address(), &amount_per_installment);

        // 2. توزيع الرسوم من رصيد العقد
        Self::_call_distribute_fees(&env, installment_fee, c.guarantee_reserve_alloc_percent);

        // 3. تحويل الصافي إلى المنشئ
        Self::_transfer(&env, &token, &c.creator, net_amount);

        if installment_num >= MAX_INSTALLMENTS {
            c.status = S_COMPLET;
            Self::_add_reputation(&env, &c.creator, REPUTATION.3);
            Self::_add_reputation(&env, &c.counterparty, REPUTATION.3);
        }

        Self::_save_commitment(&env, id, &c);
        env.events().publish((symbol_short!("install"),), InstallmentPaid {
            id,
            installment: installment_num,
            amount: net_amount,
        });

        Self::_unlock(&env);
    }

    // ===== ADMIN FUNCTIONS =====
    pub fn update_platform_wallet(env: Env, admin: Address, new_wallet: Address) {
        Self::_lock(&env);
        if admin != env.storage().persistent().get::<_, Address>(&DataKey::Admin).unwrap() {
            panic!("Unauthorized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::PlatformWallet, &new_wallet);
        Self::_extend_ttl(&env, &DataKey::PlatformWallet);
        env.events().publish((symbol_short!("upd_plat"),), new_wallet);
        Self::_unlock(&env);
    }

    pub fn update_reserve_wallet(env: Env, admin: Address, new_wallet: Address) {
        Self::_lock(&env);
        if admin != env.storage().persistent().get::<_, Address>(&DataKey::Admin).unwrap() {
            panic!("Unauthorized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::GuaranteeReserveWallet, &new_wallet);
        Self::_extend_ttl(&env, &DataKey::GuaranteeReserveWallet);
        env.events().publish((symbol_short!("upd_res"),), new_wallet);
        Self::_unlock(&env);
    }

    pub fn update_dao_wallet(env: Env, admin: Address, new_wallet: Address) {
        Self::_lock(&env);
        if admin != env.storage().persistent().get::<_, Address>(&DataKey::Admin).unwrap() {
            panic!("Unauthorized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::DaoWallet, &new_wallet);
        Self::_extend_ttl(&env, &DataKey::DaoWallet);
        env.events().publish((symbol_short!("upd_dao"),), new_wallet);
        Self::_unlock(&env);
    }

    pub fn admin_force_unlock(env: Env, admin: Address) {
        if admin != env.storage().persistent().get::<_, Address>(&DataKey::Admin).unwrap() {
            panic!("Unauthorized");
        }
        admin.require_auth();
        env.storage().instance().set(&LOCK_KEY, &false);
        env.storage().instance().extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    // ===== VIEW FUNCTIONS =====
    pub fn get_commitment(env: Env, id: u64) -> Commitment { Self::_get_commitment(&env, id) }
    pub fn get_reputation(env: Env, user: Address) -> i128 { Self::_get_reputation(&env, &user) }
    pub fn get_pool(env: Env) -> LiquidityPoolState { Self::_get_liquidity_pool(&env) }
    pub fn get_total_escrow(env: Env) -> i128 { Self::_get_total_escrow(&env) }
    pub fn get_admin(env: Env) -> Address { env.storage().persistent().get(&DataKey::Admin).unwrap() }
    pub fn get_platform_wallet(env: Env) -> Address { env.storage().persistent().get(&DataKey::PlatformWallet).unwrap() }
    pub fn get_reserve_wallet(env: Env) -> Address { env.storage().persistent().get(&DataKey::GuaranteeReserveWallet).unwrap() }
    pub fn get_dao_wallet(env: Env) -> Address { env.storage().persistent().get(&DataKey::DaoWallet).unwrap() }
  }
