import { db, MEMBER_SELECT, type MemberRow } from "./db.ts";
import { HttpError } from "./http.ts";
import { importMembers } from "./importer.ts";
import {
  deleteNotification,
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
  notifyMembers,
  passwordRequestRecipients,
} from "./notifications.ts";
import {
  assignableRolesBelow,
  canManage,
  isPlatformRole,
  parseAssignableRole,
  placementError,
  type Placement,
  type Role,
} from "./rules.ts";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALLOWED_WHILE_PASSWORD_CHANGE = new Set(["me", "passwordChanged", "profile", "listNotifications", "markNotificationRead", "markAllNotificationsRead", "deleteNotification"]);

export function placementOf(row: MemberRow): Placement {
  return { role: row.role, companyId: row.company_id, branchId: row.branch_id, teamId: row.team_id };
}

export function toMemberDto(row: MemberRow, manageable: boolean) {
  return {
    id: row.id,
    email: row.email,
    fullNameEn: row.full_name_en,
    fullNameAr: row.full_name_ar,
    userId: row.user_id,
    phone: row.phone,
    rosterOrder: row.roster_order,
    role: row.role,
    status: row.status,
    mustChangePassword: row.must_change_password,
    companyId: row.company_id,
    companyName: row.companies?.name ?? null,
    branchId: row.branch_id,
    branchName: row.branches?.name ?? null,
    teamId: row.team_id,
    teamName: row.teams?.name ?? null,
    customRankId: row.custom_rank_id ?? null,
    customRankName: row.custom_ranks?.name_ar ?? row.custom_ranks?.name ?? null,
    customRankPermissions: row.custom_ranks?.rank_permissions?.map((item) => item.permission) ?? [],
    canManage: manageable,
  };
}

export async function performAction(actor: MemberRow, body: Record<string, unknown>) {
  if (actor.must_change_password && !ALLOWED_WHILE_PASSWORD_CHANGE.has(String(body.action))) {
    throw new HttpError(403, "password_change_required");
  }
  switch (body.action) {
    case "me":
      return { member: toMemberDto(actor, false) };
    case "list":
      return listMembers(actor);
    case "import":
      return importMembers(actor, body);
    case "createCompany":
      return createCompany(actor, body);
    case "createCompanyWithAdmin":
      return createCompanyWithAdmin(actor, body);
    case "addCompanyAssistant":
      return addCompanyAssistant(actor, body);
    case "update":
      return updateMember(actor, body);
    case "remove":
      return removeMember(actor, body);
    case "passwordChanged":
      return finishPasswordChange(actor);
    case "resetPassword":
      return resetMemberPassword(actor, body);
    case "profile":
      return updateProfile(actor, body);
    case "createBranch":
      return createBranch(actor, body);
    case "updateBranch":
      return updateBranch(actor, body);
    case "deleteBranch":
      return deleteBranch(actor, body);
    case "listRanks":
      return listRanks(actor);
    case "createRank":
      return createRank(actor, body);
    case "updateRank":
      return updateRank(actor, body);
    case "deleteRank":
      return deleteRank(actor, body);
    case "listPasswordRequests":
      return listPasswordRequests(actor);
    case "createPasswordRequest":
      return createPasswordRequest(actor, body);
    case "checkPasswordRequest":
      return checkPasswordRequest(actor, body);
    case "reviewPasswordRequest":
      return reviewPasswordRequest(actor, body);
    case "platformStats":
      return platformStats(actor);
    case "listNotifications":
      return listNotifications(actor);
    case "markNotificationRead":
      return markNotificationRead(actor, body);
    case "markAllNotificationsRead":
      return markAllNotificationsRead(actor);
    case "deleteNotification":
      return deleteNotification(actor, body);
    case "listTasks":
      return listTasks(actor, body);
    case "importTasks":
      return importTasks(actor, body);
    case "createTask":
      return createTask(actor, body);
    case "updateTaskStatus":
      return updateTaskStatus(actor, body);
    case "toggleCompanyStatus":
      return toggleCompanyStatus(actor, body);
    case "listCompanyAdmins":
      return listCompanyAdmins(actor);
    case "toggleAdminStatus":
      return toggleAdminStatus(actor, body);
    case "listCompanies":
      return listCompanies(actor);
    default:
      throw new HttpError(400, "unknown_action");
  }
}

async function platformStats(actor: MemberRow) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const [companies, admins, employees, pending, approved] = await Promise.all([
    db.from("companies").select("id", { count: "exact", head: true }),
    db.from("members").select("id", { count: "exact", head: true }).eq("role", "COMPANY_ADMIN"),
    db.from("members").select("id", { count: "exact", head: true }).not("company_id", "is", null),
    db.from("password_change_requests").select("id", { count: "exact", head: true }).eq("status", "pending").eq("target_role", "platform"),
    db.from("password_change_requests").select("id", { count: "exact", head: true }).eq("status", "approved").gte("reviewed_at", since),
  ]);
  for (const result of [companies, admins, employees, pending, approved]) {
    if (result.error) throw new HttpError(500, "stats_failed");
  }
  return {
    companies: companies.count ?? 0,
    companyAdmins: admins.count ?? 0,
    employees: employees.count ?? 0,
    pendingPasswordRequests: pending.count ?? 0,
    recentlyApprovedPasswordRequests: approved.count ?? 0,
  };
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) throw new HttpError(422, `invalid_${field}`);
  return value.trim();
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function optionalUuid(value: unknown, field: string): string | null {
  const text = optionalString(value);
  if (text === null) return null;
  if (!UUID_PATTERN.test(text)) throw new HttpError(422, `invalid_${field}`);
  return text;
}

async function loadMember(id: string): Promise<MemberRow> {
  const { data, error } = await db.from("members").select(MEMBER_SELECT).eq("id", id).maybeSingle();
  if (error) throw error;
  if (!data) throw new HttpError(404, "not_found");
  return data as MemberRow;
}

function hasCustomPermission(actor: MemberRow, permission: string): boolean {
  return actor.custom_ranks?.rank_permissions?.some((item) => item.permission === permission) ?? false;
}

async function customRankMemberIds(actor: MemberRow): Promise<string[] | null> {
  if (!actor.custom_rank_id) return null;
  const { data: rank, error } = await db.from("custom_ranks").select("scope").eq("id", actor.custom_rank_id).maybeSingle();
  if (error || !rank) return null;
  if (rank.scope === "company") return null;
  if (rank.scope === "branch" && actor.branch_id) return null;
  if (rank.scope === "specific") {
    const { data: rmembers, error: rmError } = await db.from("rank_members").select("member_id").eq("rank_id", actor.custom_rank_id);
    if (rmError) return null;
    return (rmembers ?? []).map((m: { member_id: string }) => m.member_id);
  }
  return null;
}

function scopedMembersQuery(actor: MemberRow) {
  const query = db
    .from("members")
    .select(MEMBER_SELECT)
    .order("roster_order", { ascending: true, nullsFirst: false })
    .order("full_name_en");
  if (isPlatformRole(actor.role)) return query.eq("id", actor.id);
  if (actor.role === "COMPANY_ADMIN" && actor.company_id) return query.eq("company_id", actor.company_id);
  if (actor.role === "BRANCH_MANAGER" && actor.branch_id) return query.eq("branch_id", actor.branch_id);
  if (actor.company_id && (hasCustomPermission(actor, "employee.view") || hasCustomPermission(actor, "employee.import") || hasCustomPermission(actor, "employee.transfer"))) {
    if (actor.branch_id && actor.custom_ranks?.scope === "branch") return query.eq("branch_id", actor.branch_id);
    return query.eq("company_id", actor.company_id);
  }
  if (actor.role === "TEAM_LEADER" && actor.team_id) return query.eq("team_id", actor.team_id);
  return query.eq("id", actor.id);
}

async function listMembers(actor: MemberRow) {
  let baseQuery = scopedMembersQuery(actor);
  const specificIds = await customRankMemberIds(actor);
  if (specificIds) {
    baseQuery = baseQuery.in("id", specificIds.length > 0 ? specificIds : [actor.id]);
  }
  const { data, error } = await baseQuery;
  if (error) throw error;
  const me = placementOf(actor);
  const customCanManage = hasCustomPermission(actor, "employee.promote") || hasCustomPermission(actor, "employee.suspend") || hasCustomPermission(actor, "employee.revoke") || hasCustomPermission(actor, "employee.transfer");
  const members = ((data ?? []) as MemberRow[]).map((row) =>
    toMemberDto(
      row,
      row.id !== actor.id && (customCanManage
        ? (specificIds
            ? specificIds.includes(row.id)
            : actor.custom_ranks?.scope === "branch"
              ? row.branch_id === actor.branch_id && row.role !== "COMPANY_ADMIN" && !isPlatformRole(row.role)
              : row.company_id === actor.company_id && row.role !== "OWNER" && row.role !== "SUPER_ADMIN")
        : canManage(me, placementOf(row))),
    ),
  );
  return {
    members,
    lookups: await loadLookups(actor),
    assignableRoles: assignableRolesBelow(actor.role),
  };
}

async function loadLookups(actor: MemberRow) {
  const empty = { companies: [], branches: [], teams: [] };
  if (isPlatformRole(actor.role)) return empty;
  if (actor.role === "EMPLOYEE" && !hasCustomPermission(actor, "employee.view") && !hasCustomPermission(actor, "employee.import")) return empty;
  if (!actor.company_id) return empty;
  if (actor.role === "EMPLOYEE" && actor.company_id) {
    const { data: companyData, error: companyError } = await db.from("companies").select("id, name, trade_license").eq("id", actor.company_id);
    if (companyError) throw companyError;
    const { data: branchData, error: branchError } = await db.from("branches").select("id, company_id, name").eq("company_id", actor.company_id).order("name");
    if (branchError) throw branchError;
    const branchIds = (branchData ?? []).map((branch: { id: string }) => branch.id);
    const { data: teamData, error: teamError } = branchIds.length > 0
      ? await db.from("teams").select("id, branch_id, name").in("branch_id", branchIds).order("name")
      : { data: [], error: null };
    if (teamError) throw teamError;
    return { companies: companyData ?? [], branches: branchData ?? [], teams: teamData ?? [] };
  }
  if (!platform && actor.role !== "COMPANY_ADMIN" && !actor.branch_id) return empty;
  if (!platform && actor.role === "TEAM_LEADER" && !actor.team_id) return empty;

  let companies = db.from("companies").select("id, name, trade_license").order("name");
  let branches = db.from("branches").select("id, company_id, name").order("name");
  if (!platform) {
    companies = companies.eq("id", actor.company_id);
    branches =
      actor.role === "COMPANY_ADMIN"
        ? branches.eq("company_id", actor.company_id)
        : branches.eq("id", actor.branch_id as string);
  }
  const [companyRes, branchRes] = await Promise.all([companies, branches]);
  if (companyRes.error) throw companyRes.error;
  if (branchRes.error) throw branchRes.error;

  let teams = db.from("teams").select("id, branch_id, name").order("name");
  if (actor.role === "TEAM_LEADER") teams = teams.eq("id", actor.team_id as string);
  else if (!platform) teams = teams.in("branch_id", (branchRes.data ?? []).map((b: { id: string }) => b.id));
  const teamRes = (branchRes.data ?? []).length === 0 && !platform ? { data: [], error: null } : await teams;
  if (teamRes.error) throw teamRes.error;

  return { companies: companyRes.data ?? [], branches: branchRes.data ?? [], teams: teamRes.data ?? [] };
}

async function assertPlacementExists(p: Placement) {
  if (p.companyId) {
    const { data, error } = await db.from("companies").select("id").eq("id", p.companyId).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(422, "invalid_placement");
  }
  if (p.branchId) {
    const { data, error } = await db.from("branches").select("id, company_id").eq("id", p.branchId).maybeSingle();
    if (error) throw error;
    if (!data || data.company_id !== p.companyId) throw new HttpError(422, "invalid_placement");
  }
  if (p.teamId) {
    const { data, error } = await db.from("teams").select("id, branch_id").eq("id", p.teamId).maybeSingle();
    if (error) throw error;
    if (!data || data.branch_id !== p.branchId) throw new HttpError(422, "invalid_placement");
  }
}

async function updateMember(actor: MemberRow, body: Record<string, unknown>) {
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const target = await loadMember(id);
  if (target.id === actor.id) throw new HttpError(403, "cannot_edit_self");

  const me = placementOf(actor);
  if (!canManage(me, placementOf(target))) throw new HttpError(403, "forbidden");

  const fields = (typeof body.fields === "object" && body.fields !== null ? body.fields : {}) as Record<string, unknown>;
  const fullNameEn = requireString(fields.fullNameEn, "name");
  const fullNameAr = optionalString(fields.fullNameAr);
  const role = parseAssignableRole(requireString(fields.role, "role"));
  if (!role || !assignableRolesBelow(actor.role).includes(role)) throw new HttpError(403, "forbidden_role");
  if (fields.status !== "Active" && fields.status !== "Suspended") throw new HttpError(422, "invalid_status");

  const next: Placement = {
    role,
    companyId: optionalUuid(fields.companyId, "company"),
    branchId: optionalUuid(fields.branchId, "branch"),
    teamId: optionalUuid(fields.teamId, "team"),
  };
  const missing = placementError(next);
  if (missing) throw new HttpError(422, missing);
  await assertPlacementExists(next);
  if (!canManage(me, next)) throw new HttpError(403, "out_of_scope");

  const { error } = await db
    .from("members")
    .update({
      full_name_en: fullNameEn,
      full_name_ar: fullNameAr,
      role: next.role,
      status: fields.status,
      company_id: next.companyId,
      branch_id: next.branchId,
      team_id: next.teamId,
      custom_rank_id: optionalUuid(fields.customRankId, "rank") ?? null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", id);
  if (error) throw error;
  return { member: toMemberDto(await loadMember(id), true) };
}

async function removeMember(actor: MemberRow, body: Record<string, unknown>) {
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const target = await loadMember(id);
  if (target.id === actor.id) throw new HttpError(403, "cannot_edit_self");
  if (!canManage(placementOf(actor), placementOf(target))) throw new HttpError(403, "forbidden");
  const { error } = await db.from("members").delete().eq("id", id);
  if (error) throw error;
  return { ok: true };
}

async function createCompany(actor: MemberRow, body: Record<string, unknown>) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const name = requireString(body.name, "company");
  const tradeLicense = optionalString(body.tradeLicense);
  const { data, error } = await db.from("companies").insert({ name, trade_license: tradeLicense }).select("id, name, trade_license").maybeSingle();
  if (error) throw error;
  if (!data) throw new HttpError(422, "invalid_company");
  return { company: data };
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USER_ID_PATTERN = /^[0-9]{7}$/;

async function createCompanyWithAdmin(actor: MemberRow, body: Record<string, unknown>) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const name = requireString(body.companyName, "company");
  const tradeLicense = optionalString(body.tradeLicense);
  const adminName = requireString(body.adminName, "admin_name");
  const adminNameAr = optionalString(body.adminNameAr);
  const adminEmail = requireString(body.adminEmail, "admin_email").toLowerCase();
  if (!EMAIL_PATTERN.test(adminEmail)) throw new HttpError(422, "invalid_admin_email");
  const adminPassword = requireString(body.adminPassword, "admin_password");
  if (adminPassword.length < 8) throw new HttpError(422, "password_too_short");

  const { data: companyData, error: companyError } = await db
    .from("companies").insert({ name, trade_license: tradeLicense }).select("id, name, trade_license").maybeSingle();
  if (companyError) throw companyError;
  if (!companyData) throw new HttpError(422, "invalid_company");

  const { data: existingMember, error: checkError } = await db
    .from("members").select("id").eq("email", adminEmail).maybeSingle();
  if (checkError) throw checkError;
  if (existingMember) {
    await db.from("companies").delete().eq("id", companyData.id);
    throw new HttpError(422, "email_taken");
  }

  const { data: maxRow, error: maxError } = await db
    .from("members").select("user_id").order("user_id", { ascending: false }).limit(1).maybeSingle();
  if (maxError) throw maxError;
  const nextUserId = maxRow?.user_id
    ? String(Number(maxRow.user_id) + 1).padStart(7, "0")
    : "1000001";
  if (!USER_ID_PATTERN.test(nextUserId)) throw new HttpError(500, "user_id_overflow");

  const { error: memberError } = await db.from("members").insert({
    email: adminEmail,
    full_name_en: adminName,
    full_name_ar: adminNameAr,
    username: nextUserId,
    user_id: nextUserId,
    role: "COMPANY_ADMIN",
    company_id: companyData.id,
    status: "Active",
    must_change_password: true,
  });
  if (memberError) {
    await db.from("companies").delete().eq("id", companyData.id);
    throw memberError;
  }

  try {
    const { provisionFirebaseAccount } = await import("./firebaseAdmin.ts");
    await provisionFirebaseAccount(adminEmail, adminPassword);
  } catch (e) {
    console.error("Failed to provision Firebase account for admin:", e);
  }

  return { company: companyData, admin: { email: adminEmail, userId: nextUserId } };
}

async function updateProfile(actor: MemberRow, body: Record<string, unknown>) {
  const fields = (typeof body.fields === "object" && body.fields !== null ? body.fields : {}) as Record<string, unknown>;
  const fullNameEn = requireString(fields.fullNameEn, "name");
  const fullNameAr = optionalString(fields.fullNameAr);
  const phone = optionalString(fields.phone);
  if (phone && !/^[+0-9 ()-]{7,24}$/.test(phone)) throw new HttpError(422, "invalid_phone");
  const { error } = await db
    .from("members")
    .update({ full_name_en: fullNameEn, full_name_ar: fullNameAr, phone, updated_at: new Date().toISOString() })
    .eq("id", actor.id);
  if (error) throw error;
  return { member: toMemberDto(await loadMember(actor.id), false) };
}

async function finishPasswordChange(actor: MemberRow) {
  const { error } = await db
    .from("members")
    .update({ must_change_password: false, updated_at: new Date().toISOString() })
    .eq("id", actor.id);
  if (error) throw error;
  return { ok: true };
}

async function resetMemberPassword(actor: MemberRow, body: Record<string, unknown>) {
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const target = await loadMember(id);
  if (target.id === actor.id) throw new HttpError(403, "cannot_edit_self");
  if (!canManage(placementOf(actor), placementOf(target))) throw new HttpError(403, "forbidden");

  const email = requireString(body.email, "email");
  if (email !== target.email.toLowerCase()) throw new HttpError(422, "email_mismatch");

  const newPassword = requireString(body.newPassword, "password");
  if (newPassword.length < 8) throw new HttpError(422, "password_too_short");

  try {
    const { updateFirebasePassword } = await import("./firebaseAdmin.ts");
    await updateFirebasePassword(target.email, newPassword);
  } catch (e) {
    console.error("Failed to update Firebase password:", e);
    throw new HttpError(500, "password_update_failed");
  }
  const { error } = await db
    .from("members")
    .update({
      must_change_password: true,
      updated_at: new Date().toISOString(),
    })
    .eq("id", id);
  if (error) throw error;
  return { ok: true };
}

// ── Branches ──────────────────────────────────────────────────

async function createBranch(actor: MemberRow, body: Record<string, unknown>) {
  if (!actor.company_id) throw new HttpError(403, "forbidden");
  if (actor.role !== "COMPANY_ADMIN" && !isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const name = requireString(body.name, "branch");
  const companyId = isPlatformRole(actor.role) ? optionalUuid(body.companyId, "company") : actor.company_id;
  if (!companyId) throw new HttpError(422, "invalid_company");
  const { data, error } = await db
    .from("branches").insert({ name, company_id: companyId }).select("id, company_id, name").maybeSingle();
  if (error) throw error;
  if (!data) throw new HttpError(422, "invalid_branch");
  return { branch: data };
}

async function loadBranchForActor(actor: MemberRow, body: Record<string, unknown>) {
  const id = optionalUuid(body.id, "branch");
  if (!id) throw new HttpError(422, "invalid_branch");
  const query = db.from("branches").select("id, company_id, name").eq("id", id);
  const scoped = isPlatformRole(actor.role) ? query : query.eq("company_id", actor.company_id);
  const { data, error } = await scoped.maybeSingle();
  if (error) throw error;
  if (!data) throw new HttpError(404, "not_found");
  return data as { id: string; company_id: string; name: string };
}

async function updateBranch(actor: MemberRow, body: Record<string, unknown>) {
  if (actor.role !== "COMPANY_ADMIN" && !isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const branch = await loadBranchForActor(actor, body);
  const name = requireString(body.name, "branch");
  const { error } = await db.from("branches").update({ name }).eq("id", branch.id);
  if (error) throw error;
  return { ok: true };
}

async function deleteBranch(actor: MemberRow, body: Record<string, unknown>) {
  if (actor.role !== "COMPANY_ADMIN" && !isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const branch = await loadBranchForActor(actor, body);
  const { count, error: countError } = await db.from("members").select("id", { count: "exact", head: true }).eq("branch_id", branch.id);
  if (countError) throw countError;
  if ((count ?? 0) > 0) throw new HttpError(409, "branch_has_members");
  const { count: teamCount, error: teamError } = await db.from("teams").select("id", { count: "exact", head: true }).eq("branch_id", branch.id);
  if (teamError) throw teamError;
  if ((teamCount ?? 0) > 0) throw new HttpError(409, "branch_has_teams");
  const { error } = await db.from("branches").delete().eq("id", branch.id);
  if (error) throw error;
  return { ok: true };
}

// ── Custom Ranks ──────────────────────────────────────────────

const VALID_PERMISSIONS = [
  "branch.manage",
  "employee.import",
  "target.import",
  "sale.create",
  "sale.approve",
  "employee.promote",
  "employee.suspend",
  "employee.revoke",
  "employee.transfer",
  "password.approve",
  "performance.review",
] as const;

function assertCompanyAdmin(actor: MemberRow) {
  if (actor.role !== "COMPANY_ADMIN" && !isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  if (!actor.company_id && !isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
}

function rankCompanyId(actor: MemberRow, body: Record<string, unknown>): string {
  if (isPlatformRole(actor.role)) {
    const id = optionalUuid(body.companyId, "company");
    if (!id) throw new HttpError(422, "invalid_company");
    return id;
  }
  return actor.company_id as string;
}

async function listRanks(actor: MemberRow) {
  assertCompanyAdmin(actor);
  const cid = isPlatformRole(actor.role) ? null : actor.company_id;
  let query = db.from("custom_ranks").select("id, company_id, name, name_ar, scope, created_at").order("created_at", { ascending: false });
  if (cid) query = query.eq("company_id", cid);
  const { data: ranks, error } = await query;
  if (error) throw error;
  if (!ranks || ranks.length === 0) return { ranks: [] };
  const rankIds = ranks.map((r: { id: string }) => r.id);
  const { data: perms, error: permError } = await db
    .from("rank_permissions").select("rank_id, permission").in("rank_id", rankIds);
  if (permError) throw permError;
  const { data: rmembers, error: rmError } = await db
    .from("rank_members").select("rank_id, member_id").in("rank_id", rankIds);
  if (rmError) throw rmError;
  const permMap = new Map<string, string[]>();
  for (const p of (perms ?? []) as { rank_id: string; permission: string }[]) {
    const arr = permMap.get(p.rank_id) ?? [];
    arr.push(p.permission);
    permMap.set(p.rank_id, arr);
  }
  const memberMap = new Map<string, string[]>();
  for (const m of (rmembers ?? []) as { rank_id: string; member_id: string }[]) {
    const arr = memberMap.get(m.rank_id) ?? [];
    arr.push(m.member_id);
    memberMap.set(m.rank_id, arr);
  }
  return {
    ranks: ranks.map((r: { id: string; company_id: string; name: string; name_ar: string | null; scope: string; created_at: string }) => ({
      id: r.id,
      companyId: r.company_id,
      name: r.name,
      nameAr: r.name_ar,
      scope: r.scope,
      permissions: permMap.get(r.id) ?? [],
      memberIds: memberMap.get(r.id) ?? [],
      createdAt: r.created_at,
    })),
  };
}

const VALID_SCOPES = ["company", "branch", "specific"] as const;

async function createRank(actor: MemberRow, body: Record<string, unknown>) {
  assertCompanyAdmin(actor);
  const name = requireString(body.name, "rank_name");
  const nameAr = optionalString(body.nameAr);
  const cid = rankCompanyId(actor, body);
  const permissions = Array.isArray(body.permissions) ? body.permissions : [];
  for (const p of permissions) {
    if (!VALID_PERMISSIONS.includes(p as (typeof VALID_PERMISSIONS)[number])) throw new HttpError(422, "invalid_permission");
  }
  const scope = typeof body.scope === "string" && VALID_SCOPES.includes(body.scope as (typeof VALID_SCOPES)[number]) ? body.scope : "company";
  const { data: rank, error: rankError } = await db
    .from("custom_ranks").insert({ name, name_ar: nameAr, company_id: cid, scope }).select("id").maybeSingle();
  if (rankError) throw rankError;
  if (!rank) throw new HttpError(422, "invalid_rank");
  if (permissions.length > 0) {
    const rows = permissions.map((p: string) => ({ rank_id: rank.id, permission: p }));
    const { error: permError } = await db.from("rank_permissions").insert(rows);
    if (permError) throw permError;
  }
  await syncRankMembers(rank.id, cid, body.memberIds);
  return { rankId: rank.id };
}

async function updateRank(actor: MemberRow, body: Record<string, unknown>) {
  assertCompanyAdmin(actor);
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const cid = isPlatformRole(actor.role) ? null : actor.company_id;
  let checkQuery = db.from("custom_ranks").select("id, company_id").eq("id", id);
  if (cid) checkQuery = checkQuery.eq("company_id", cid);
  const { data: existing, error: checkError } = await checkQuery.maybeSingle();
  if (checkError) throw checkError;
  if (!existing) throw new HttpError(404, "not_found");
  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (typeof body.name === "string" && body.name.trim()) updates.name = body.name.trim();
  if (typeof body.nameAr === "string") updates.name_ar = body.nameAr.trim() || null;
  if (Object.keys(updates).length > 1) {
    const { error: updateError } = await db.from("custom_ranks").update(updates).eq("id", id);
    if (updateError) throw updateError;
  }
  if (Array.isArray(body.permissions)) {
    for (const p of body.permissions) {
      if (!VALID_PERMISSIONS.includes(p as (typeof VALID_PERMISSIONS)[number])) throw new HttpError(422, "invalid_permission");
    }
    const { error: delError } = await db.from("rank_permissions").delete().eq("rank_id", id);
    if (delError) throw delError;
    if (body.permissions.length > 0) {
      const rows = (body.permissions as string[]).map((p) => ({ rank_id: id, permission: p }));
      const { error: insError } = await db.from("rank_permissions").insert(rows);
      if (insError) throw insError;
    }
  }
  if (typeof body.scope === "string" && VALID_SCOPES.includes(body.scope as (typeof VALID_SCOPES)[number])) {
    const { error: scopeError } = await db.from("custom_ranks").update({ scope: body.scope, updated_at: new Date().toISOString() }).eq("id", id);
    if (scopeError) throw scopeError;
  }
  if (Array.isArray(body.memberIds)) {
    await syncRankMembers(id, (existing as { company_id: string }).company_id, body.memberIds);
  }
  return { ok: true };
}

async function syncRankMembers(rankId: string, companyId: string, rawMemberIds: unknown) {
  if (!Array.isArray(rawMemberIds)) return;
  const memberIds = (rawMemberIds as unknown[]).filter((m): m is string => typeof m === "string" && UUID_PATTERN.test(m));
  if (memberIds.length === 0) return;
  const { data: valid, error } = await db.from("members").select("id").eq("company_id", companyId).in("id", memberIds);
  if (error) throw error;
  const validIds = (valid ?? []).map((m: { id: string }) => m.id);
  if (validIds.length === 0) return;
  const { error: delError } = await db.from("rank_members").delete().eq("rank_id", rankId);
  if (delError) throw delError;
  const rows = validIds.map((mid: string) => ({ rank_id: rankId, member_id: mid }));
  const { error: insError } = await db.from("rank_members").insert(rows);
  if (insError) throw insError;
}

async function deleteRank(actor: MemberRow, body: Record<string, unknown>) {
  assertCompanyAdmin(actor);
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const cid = isPlatformRole(actor.role) ? null : actor.company_id;
  let checkQuery = db.from("custom_ranks").select("id, company_id").eq("id", id);
  if (cid) checkQuery = checkQuery.eq("company_id", cid);
  const { data: existing, error: checkError } = await checkQuery.maybeSingle();
  if (checkError) throw checkError;
  if (!existing) throw new HttpError(404, "not_found");
  const { error } = await db.from("custom_ranks").delete().eq("id", id);
  if (error) throw error;
  return { ok: true };
}

async function addCompanyAssistant(actor: MemberRow, body: Record<string, unknown>) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const companyId = optionalUuid(body.companyId, "company");
  if (!companyId) throw new HttpError(422, "invalid_company");
  const name = requireString(body.name, "assistant_name");
  const nameAr = optionalString(body.nameAr);
  const email = requireString(body.email, "assistant_email").toLowerCase();
  if (!EMAIL_PATTERN.test(email)) throw new HttpError(422, "invalid_email");
  const password = requireString(body.password, "assistant_password");
  if (password.length < 8) throw new HttpError(422, "password_too_short");

  const { data: existing } = await db.from("members").select("id").eq("email", email).maybeSingle();
  if (existing) throw new HttpError(422, "email_taken");

  const { data: maxRow } = await db.from("members").select("user_id").order("user_id", { ascending: false }).limit(1).maybeSingle();
  const nextUserId = maxRow?.user_id ? String(Number(maxRow.user_id) + 1).padStart(7, "0") : "1000001";
  if (!USER_ID_PATTERN.test(nextUserId)) throw new HttpError(500, "user_id_overflow");

  const { error } = await db.from("members").insert({
    email,
    full_name_en: name,
    full_name_ar: nameAr,
    username: nextUserId,
    user_id: nextUserId,
    role: "COMPANY_ADMIN",
    company_id: companyId,
    is_assistant: true,
    status: "Active",
    must_change_password: true,
  });
  if (error) throw error;
  try {
    const { provisionFirebaseAccount } = await import("./firebaseAdmin.ts");
    await provisionFirebaseAccount(email, password);
  } catch (e) {
    console.error("Failed to provision Firebase account for assistant:", e);
  }
  return { assistant: { email, userId: nextUserId } };
}

// ── Password Change Requests ──────────────────────────────────

// Company managers' requests go to platform owners; everyone else in a company goes to the company admin.
function requestTargetRole(role: Role): "platform" | "company" {
  return isPlatformRole(role) || role === "COMPANY_ADMIN" ? "platform" : "company";
}

async function listPasswordRequests(actor: MemberRow) {
  if (actor.role === "EMPLOYEE" && !hasCustomPermission(actor, "password.approve")) throw new HttpError(403, "forbidden");
  const platform = isPlatformRole(actor.role);
  let query = db
    .from("password_change_requests")
    .select("id, member_id, company_id, status, requested_at, reviewed_at, reviewed_by, note, target_role, browser_fingerprint, members!member_id(full_name_en, email, user_id, role), companies(name)")
    .order("requested_at", { ascending: false })
    .neq("member_id", actor.id);
  if (platform) {
    query = query.eq("target_role", "platform");
  } else {
    query = query.eq("company_id", actor.company_id as string).or("target_role.eq.company,target_role.is.null");
  }
  const { data, error } = await query;
  if (error) throw error;
  return { requests: data ?? [] };
}

export async function requestPasswordByEmail(body: Record<string, unknown>) {
  const email = requireString(body.email, "email").toLowerCase();
  const fingerprint = optionalString(body.browserFingerprint);
  const { data: member, error } = await db.from("members").select("id, company_id, role").eq("email", email).maybeSingle();
  if (error) throw error;
  if (member) {
    const targetRole = requestTargetRole(member.role as Role);
    let existingQuery = db
      .from("password_change_requests")
      .select("id")
      .eq("member_id", member.id)
      .eq("status", "pending");
    if (fingerprint) existingQuery = existingQuery.eq("browser_fingerprint", fingerprint);
    const { data: existing } = await existingQuery.maybeSingle();
    if (!existing) {
      const { error: insertError } = await db.from("password_change_requests").insert({
        member_id: member.id,
        company_id: member.company_id,
        status: "pending",
        browser_fingerprint: fingerprint,
        target_role: targetRole,
      });
      if (insertError) throw insertError;
    }
  }
  return { ok: true };
}

async function createPasswordRequest(actor: MemberRow, body: Record<string, unknown>) {
  const fingerprint = optionalString(body.browserFingerprint);
  const isPlatformOwner = isPlatformRole(actor.role);
  if (!isPlatformOwner && !actor.company_id) throw new HttpError(403, "forbidden");

  let existingQuery = db
    .from("password_change_requests")
    .select("id")
    .eq("member_id", actor.id)
    .eq("status", "pending");
  if (fingerprint) existingQuery = existingQuery.eq("browser_fingerprint", fingerprint);
  const { data: existing } = await existingQuery.maybeSingle();
  if (existing) throw new HttpError(422, "request_already_pending");

  const targetRole = requestTargetRole(actor.role);
  const { data: created, error } = await db.from("password_change_requests").insert({
    member_id: actor.id,
    company_id: actor.company_id,
    status: "pending",
    browser_fingerprint: fingerprint,
    target_role: targetRole,
  }).select("id").single();
  if (error) throw error;
  const recipients = await passwordRequestRecipients(targetRole, actor.company_id, actor.id);
  await notifyMembers(recipients, {
    type: "password_request_created",
    title: actor.full_name_en,
    body: actor.email,
    linkPath: "/password-requests",
    dedupeKey: `password-request:${created.id}:created`,
  });
  return { ok: true };
}

async function checkPasswordRequest(actor: MemberRow, body: Record<string, unknown>) {
  const fingerprint = optionalString(body.browserFingerprint);
  if (!fingerprint) return { pending: false, approved: false };
  const { data: pendingReq, error } = await db
    .from("password_change_requests")
    .select("id, status, requested_at")
    .eq("member_id", actor.id)
    .in("status", ["pending", "approved"])
    .eq("browser_fingerprint", fingerprint)
    .order("requested_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  if (!pendingReq) return { pending: false, approved: false };
  if (pendingReq.status === "pending") return { pending: true, approved: false, requestedAt: pendingReq.requested_at };
  if (pendingReq.status === "approved") return { pending: false, approved: true, requestedAt: pendingReq.requested_at };
  return { pending: false, approved: false };
}

async function reviewPasswordRequest(actor: MemberRow, body: Record<string, unknown>) {
  if (actor.role === "EMPLOYEE" && !hasCustomPermission(actor, "password.approve")) throw new HttpError(403, "forbidden");
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const decision = requireString(body.decision, "decision");
  if (decision !== "approved" && decision !== "rejected") throw new HttpError(422, "invalid_decision");
  const platform = isPlatformRole(actor.role);
  const cid = platform ? null : actor.company_id;
  let checkQuery = db.from("password_change_requests").select("id, company_id, member_id, status, target_role").eq("id", id).eq("status", "pending");
  if (platform) checkQuery = checkQuery.eq("target_role", "platform");
  else checkQuery = checkQuery.eq("company_id", cid as string).or("target_role.eq.company,target_role.is.null");
  const { data: req, error: checkError } = await checkQuery.maybeSingle();
  if (checkError) throw checkError;
  if (!req) throw new HttpError(404, "not_found");
  if ((req as { member_id: string }).member_id === actor.id) throw new HttpError(403, "cannot_review_own_request");
  const { error } = await db.from("password_change_requests").update({
    status: decision,
    reviewed_at: new Date().toISOString(),
    reviewed_by: actor.id,
  }).eq("id", id);
  if (error) throw error;
  await notifyMembers([(req as { member_id: string }).member_id], {
    type: decision === "approved" ? "password_request_approved" : "password_request_rejected",
    title: decision,
    linkPath: "/",
    dedupeKey: `password-request:${id}:${decision}`,
  });
  if (decision === "approved") {
    const resetToken = generateResetToken();
    const tokenHash = await sha256Hex(resetToken);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await db.from("password_change_requests").update({
      reset_token_hash: tokenHash,
      expires_at: expiresAt,
    }).eq("id", id);
    await db.from("members").update({
      must_change_password: true,
      updated_at: new Date().toISOString(),
    }).eq("id", (req as { member_id: string }).member_id);
  }
  return { ok: true };
}

export async function checkPasswordRequestByEmail(body: Record<string, unknown>) {
  const email = requireString(body.email, "email").toLowerCase();
  const fingerprint = optionalString(body.browserFingerprint);
  if (!fingerprint) return { pending: false, approved: false };
  const { data: member, error: mError } = await db.from("members").select("id").eq("email", email).maybeSingle();
  if (mError) throw mError;
  if (!member) return { pending: false, approved: false };
  const { data, error } = await db
    .from("password_change_requests")
    .select("id, status, requested_at, expires_at, used_at, reset_token_hash")
    .eq("member_id", member.id)
    .in("status", ["pending", "approved"])
    .eq("browser_fingerprint", fingerprint)
    .order("requested_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  if (!data) return { pending: false, approved: false };
  if (data.status === "pending") return { pending: true, approved: false, requestedAt: data.requested_at };
  if (data.status === "approved") {
    const expired = data.expires_at && new Date(data.expires_at) < new Date();
    const used = data.used_at !== null;
    if (expired || used) return { pending: false, approved: false };
    return { pending: false, approved: true, requestedAt: data.requested_at };
  }
  return { pending: false, approved: false };
}

export async function changePasswordWithToken(body: Record<string, unknown>) {
  const email = requireString(body.email, "email").toLowerCase();
  const fingerprint = requireString(body.browserFingerprint, "browser_fingerprint");
  const newPassword = requireString(body.newPassword, "password");
  if (newPassword.length < 8) throw new HttpError(422, "password_too_short");
  const { data: member, error: mError } = await db.from("members").select("id, email").eq("email", email).maybeSingle();
  if (mError) throw mError;
  if (!member) throw new HttpError(404, "not_found");
  const { data: req, error: rError } = await db
    .from("password_change_requests")
    .select("id, status, reset_token_hash, expires_at, used_at")
    .eq("member_id", member.id)
    .eq("status", "approved")
    .eq("browser_fingerprint", fingerprint)
    .is("used_at", null)
    .order("requested_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (rError) throw rError;
  if (!req || !req.reset_token_hash) throw new HttpError(403, "no_approved_request");
  if (req.expires_at && new Date(req.expires_at) < new Date()) throw new HttpError(403, "token_expired");
  try {
    const { updateFirebasePassword } = await import("./firebaseAdmin.ts");
    await updateFirebasePassword(member.email, newPassword);
  } catch (e) {
    console.error("Failed to update Firebase password:", e);
    throw new HttpError(500, "password_update_failed");
  }
  const { error: markUsedError } = await db.from("password_change_requests").update({
    used_at: new Date().toISOString(),
  }).eq("id", req.id);
  if (markUsedError) throw markUsedError;
  const { error: clearMustChange } = await db.from("members").update({
    must_change_password: false,
    updated_at: new Date().toISOString(),
  }).eq("id", member.id);
  if (clearMustChange) throw clearMustChange;
  return { ok: true };
}

// ── Tasks ──────────────────────────────────────────────────────

const MAX_TASK_ROWS = 500;
const TASK_PRIORITIES = ["low", "medium", "high", "urgent"] as const;
const TASK_STATUSES = ["pending", "in_progress", "completed", "cancelled"] as const;

async function listTasks(actor: MemberRow, body: Record<string, unknown>) {
  if (isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  let query = db
    .from("tasks")
    .select("id, title, description, assigned_to, due_date, priority, status, import_batch_id, created_at, created_by, members!tasks_assigned_to_fkey(full_name_en, email, user_id)")
    .order("created_at", { ascending: false });
  if (actor.role === "COMPANY_ADMIN" && actor.company_id) {
    query = query.eq("company_id", actor.company_id);
  } else if (actor.role === "BRANCH_MANAGER" && actor.branch_id) {
    query = query.or(`branch_id.eq.${actor.branch_id},assigned_to.eq.${actor.id}`);
  } else {
    query = query.eq("assigned_to", actor.id);
  }
  const statusFilter = optionalString(body.status);
  if (statusFilter && TASK_STATUSES.includes(statusFilter as (typeof TASK_STATUSES)[number])) {
    query = query.eq("status", statusFilter);
  }
  const { data, error } = await query;
  if (error) throw error;
  return { tasks: data ?? [] };
}

async function importTasks(actor: MemberRow, body: Record<string, unknown>) {
  if (isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  if (!actor.company_id) throw new HttpError(403, "forbidden");
  if (!Array.isArray(body.rows) || body.rows.length === 0 || body.rows.length > MAX_TASK_ROWS) {
    throw new HttpError(422, "invalid_rows");
  }
  const commit = body.commit === true;
  const batchId = crypto.randomUUID();
  const issues: { line: number; code: string }[] = [];
  const parsed: { line: number; title: string; description: string | null; assignedEmail: string; dueDate: string | null; priority: string; branchId: string | null }[] = [];
  for (let i = 0; i < body.rows.length; i++) {
    const r = (typeof body.rows[i] === "object" && body.rows[i] !== null ? body.rows[i] : {}) as Record<string, unknown>;
    const line = typeof r.line === "number" ? r.line : i + 1;
    const title = requireString(r.title, "title");
    const description = optionalString(r.description);
    const assignedEmail = requireString(r.assignedEmail, "assigned_email").toLowerCase();
    if (!EMAIL_PATTERN.test(assignedEmail)) { issues.push({ line, code: "invalid_email" }); continue; }
    const dueDate = optionalString(r.dueDate);
    const priority = optionalString(r.priority) ?? "medium";
    if (!TASK_PRIORITIES.includes(priority as (typeof TASK_PRIORITIES)[number])) { issues.push({ line, code: "invalid_priority" }); continue; }
    const branchId = optionalUuid(r.branchId, "branch");
    parsed.push({ line, title, description, assignedEmail, dueDate, priority, branchId });
  }
  if (issues.length > 0) throw new HttpError(422, "validation", issues);
  const { data: assignees, error: aError } = await db.from("members").select("id, email").eq("company_id", actor.company_id).in("email", parsed.map((p) => p.assignedEmail));
  if (aError) throw aError;
  const emailToId = new Map((assignees ?? []).map((m: { id: string; email: string }) => [m.email.toLowerCase(), m.id]));
  const missing: { line: number; code: string }[] = [];
  for (const p of parsed) {
    if (!emailToId.has(p.assignedEmail)) missing.push({ line: p.line, code: "assignee_not_found" });
  }
  if (missing.length > 0) throw new HttpError(422, "validation", missing);
  if (!commit) return { valid: true, count: parsed.length };
  const rows = parsed.map((p) => ({
    company_id: actor.company_id,
    branch_id: p.branchId,
    title: p.title,
    description: p.description,
    assigned_to: emailToId.get(p.assignedEmail) as string,
    due_date: p.dueDate,
    priority: p.priority,
    status: "pending",
    import_batch_id: batchId,
    created_by: actor.id,
  }));
  const { error: insError } = await db.from("tasks").insert(rows);
  if (insError) throw insError;
  const recipientIds = Array.from(new Set(rows.map((r) => r.assigned_to)));
  await notifyMembers(recipientIds, {
    type: "task_assigned",
    title: `${parsed.length} task(s) assigned`,
    body: parsed[0]?.title ?? "",
    linkPath: "/tasks",
    dedupeKey: `task-import:${batchId}`,
  });
  return { valid: true, created: parsed.length, batchId };
}

async function updateTaskStatus(actor: MemberRow, body: Record<string, unknown>) {
  if (isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const newStatus = requireString(body.status, "status");
  if (!TASK_STATUSES.includes(newStatus as (typeof TASK_STATUSES)[number])) throw new HttpError(422, "invalid_status");
  const { data: task, error: tError } = await db.from("tasks").select("id, assigned_to, company_id, branch_id, status").eq("id", id).maybeSingle();
  if (tError) throw tError;
  if (!task) throw new HttpError(404, "not_found");
  const canAccess = task.assigned_to === actor.id ||
    (actor.role === "COMPANY_ADMIN" && task.company_id === actor.company_id) ||
    (actor.role === "BRANCH_MANAGER" && task.branch_id === actor.branch_id);
  if (!canAccess) throw new HttpError(403, "forbidden");
  const previousStatus = task.status;
  const { error: uError } = await db.from("tasks").update({ status: newStatus, updated_at: new Date().toISOString() }).eq("id", id);
  if (uError) throw uError;
  await db.from("task_status_history").insert({
    task_id: id,
    previous_status: previousStatus,
    new_status: newStatus,
    changed_by: actor.id,
  });
  return { ok: true };
}

async function createTask(actor: MemberRow, body: Record<string, unknown>) {
  if (isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  if (!actor.company_id) throw new HttpError(403, "forbidden");
  const title = requireString(body.title, "title");
  const description = optionalString(body.description);
  const assignedTo = optionalUuid(body.assignedTo, "assignee");
  const dueDate = optionalString(body.dueDate);
  const priority = optionalString(body.priority) ?? "medium";
  if (!TASK_PRIORITIES.includes(priority as (typeof TASK_PRIORITIES)[number])) throw new HttpError(422, "invalid_priority");
  const branchId = optionalUuid(body.branchId, "branch");
  if (assignedTo) {
    const { data: assignee, error } = await db.from("members").select("id, company_id").eq("id", assignedTo).maybeSingle();
    if (error) throw error;
    if (!assignee || assignee.company_id !== actor.company_id) throw new HttpError(422, "assignee_not_in_company");
  }
  const { data: task, error } = await db.from("tasks").insert({
    company_id: actor.company_id,
    branch_id: branchId,
    title,
    description,
    assigned_to: assignedTo,
    due_date: dueDate,
    priority,
    status: "pending",
    created_by: actor.id,
  }).select("id").maybeSingle();
  if (error) throw error;
  if (!task) throw new HttpError(422, "invalid_task");
  if (assignedTo) {
    await notifyMembers([assignedTo], {
      type: "task_assigned",
      title,
      body: description,
      linkPath: "/tasks",
      dedupeKey: `task:${task.id}:assigned`,
    });
  }
  return { taskId: task.id };
}

// ── Company Management ─────────────────────────────────────────

async function toggleCompanyStatus(actor: MemberRow, body: Record<string, unknown>) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const newStatus = requireString(body.status, "status");
  if (newStatus !== "active" && newStatus !== "suspended") throw new HttpError(422, "invalid_status");
  const { error } = await db.from("companies").update({ status: newStatus, updated_at: new Date().toISOString() }).eq("id", id);
  if (error) throw error;
  if (newStatus === "suspended") {
    const { data: members } = await db.from("members").select("id").eq("company_id", id);
    if (members && members.length > 0) {
      await db.from("members").update({ status: "Suspended", updated_at: new Date().toISOString() }).eq("company_id", id);
    }
  }
  return { ok: true };
}

async function listCompanyAdmins(actor: MemberRow) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const { data, error } = await db
    .from("members")
    .select("id, email, full_name_en, full_name_ar, user_id, role, status, company_id, companies(id, name, status)")
    .eq("role", "COMPANY_ADMIN")
    .order("full_name_en");
  if (error) throw error;
  return { admins: data ?? [] };
}

async function toggleAdminStatus(actor: MemberRow, body: Record<string, unknown>) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const id = optionalUuid(body.id, "id");
  if (!id) throw new HttpError(422, "invalid_id");
  const newStatus = requireString(body.status, "status");
  if (newStatus !== "Active" && newStatus !== "Suspended") throw new HttpError(422, "invalid_status");
  const { error } = await db.from("members").update({ status: newStatus, updated_at: new Date().toISOString() }).eq("id", id).eq("role", "COMPANY_ADMIN");
  if (error) throw error;
  return { ok: true };
}

async function listCompanies(actor: MemberRow) {
  if (!isPlatformRole(actor.role)) throw new HttpError(403, "forbidden");
  const { data, error } = await db
    .from("companies")
    .select("id, name, trade_license, status, created_at")
    .order("name");
  if (error) throw error;
  return { companies: data ?? [] };
}

// ── Secure Token Utilities ─────────────────────────────────────

function generateResetToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
