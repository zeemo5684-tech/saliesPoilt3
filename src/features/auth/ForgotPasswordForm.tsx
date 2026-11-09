import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useTranslation } from 'react-i18next';
import { Button } from '@/shared/ui/Button';
import { Field, inputClass } from '@/shared/ui/Field';
import { firebaseErrorCode } from '@/shared/auth/firebase';
import { useAuth } from '@/features/auth/useAuth';
import { checkPasswordRequestByEmail, createPasswordRequestByEmail, changePasswordWithToken } from '@/features/roster/rosterApi';
import { getBrowserFingerprint } from '@/shared/utils/browserFingerprint';

const schema = z.object({
  email: z.string().trim().email(),
});

type ForgotPasswordValues = z.infer<typeof schema>;

type ResetStatus = 'idle' | 'sent' | 'requested' | 'pending' | 'approved' | 'network' | 'unknown';

const PASSWORD_PATTERN = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,12}$/;
const passwordSchema = z
  .object({
    password: z.string().regex(PASSWORD_PATTERN),
    confirm: z.string(),
  })
  .refine((values) => values.password === values.confirm, { path: ['confirm'] });

type PasswordValues = z.infer<typeof passwordSchema>;

export function ForgotPasswordForm({ onBack }: { onBack: () => void }) {
  const { t } = useTranslation();
  const { sendPasswordReset, signIn } = useAuth();
  const [status, setStatus] = useState<ResetStatus>('idle');
  const [checking, setChecking] = useState(false);
  const [approvedEmail, setApprovedEmail] = useState<string>('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordValues>({
    resolver: zodResolver(schema),
    defaultValues: { email: '' },
  });
  const {
    register: registerPw,
    handleSubmit: handleSubmitPw,
    formState: { errors: errorsPw, isSubmitting: isSubmittingPw },
    reset: resetPw,
  } = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { password: '', confirm: '' },
  });

  const requestApproval = async () => {
    const emailInput = document.getElementById('reset-email') as HTMLInputElement | null;
    if (!emailInput?.value) return;
    const email = emailInput.value.trim().toLowerCase();
    const fp = getBrowserFingerprint();
    setStatus('idle');
    setChecking(true);
    try {
      const result = await checkPasswordRequestByEmail(email, fp);
      if (result.pending) {
        setStatus('pending');
        return;
      }
      if (result.approved) {
        setApprovedEmail(email);
        setStatus('approved');
        resetPw({ password: '', confirm: '' });
        return;
      }
      await createPasswordRequestByEmail(email, fp);
      setStatus('requested');
    } catch {
      setStatus('unknown');
    } finally {
      setChecking(false);
    }
  };

  const onSubmit = async (values: ForgotPasswordValues) => {
    setStatus('idle');
    try {
      await sendPasswordReset(values.email);
      setStatus('sent');
    } catch (error) {
      const code = firebaseErrorCode(error);
      if (code === 'auth/user-not-found') setStatus('sent');
      else if (code === 'auth/network-request-failed') setStatus('network');
      else setStatus('unknown');
    }
  };

  const onSubmitPassword = async (values: PasswordValues) => {
    setPasswordError(null);
    const fp = getBrowserFingerprint();
    try {
      await changePasswordWithToken(approvedEmail, fp, values.password);
      try {
        await signIn(approvedEmail, values.password);
      } catch {
        setStatus('sent');
      }
    } catch (error) {
      if (error instanceof Error) {
        const code = 'code' in error ? (error as { code: string }).code : '';
        if (code === 'token_expired') setPasswordError(t('auth.errors.tokenExpired'));
        else if (code === 'no_approved_request') setPasswordError(t('auth.errors.noApprovedRequest'));
        else if (code === 'password_update_failed') setPasswordError(t('auth.errors.generic'));
        else setPasswordError(t('auth.errors.generic'));
      } else {
        setPasswordError(t('auth.errors.generic'));
      }
    }
  };

  if (status === 'approved') {
    return (
      <div className="flex flex-col gap-6">
        <div className="rounded-lg bg-success-50 px-3 py-2 text-sm text-success-700">
          {t('auth.forgot.approved')}
        </div>
        <form onSubmit={handleSubmitPw(onSubmitPassword)} noValidate className="flex flex-col gap-5">
          <Field
            id="reset-new-password"
            label={t('auth.changePassword.newPassword')}
            hint={t('auth.changePassword.hint')}
            error={errorsPw.password && t('auth.errors.passwordInvalid')}
          >
            <input
              id="reset-new-password"
              type="password"
              autoComplete="new-password"
              dir="ltr"
              className={inputClass}
              {...registerPw('password')}
            />
          </Field>
          <Field
            id="reset-confirm-password"
            label={t('auth.changePassword.confirmPassword')}
            error={errorsPw.confirm && t('auth.errors.passwordMismatch')}
          >
            <input
              id="reset-confirm-password"
              type="password"
              autoComplete="new-password"
              dir="ltr"
              className={inputClass}
              {...registerPw('confirm')}
            />
          </Field>
          {passwordError && (
            <p role="alert" className="rounded-lg bg-error-50 px-3 py-2 text-sm text-error-700">
              {passwordError}
            </p>
          )}
          <Button type="submit" disabled={isSubmittingPw} className="w-full">
            {isSubmittingPw ? t('auth.changePassword.submitting') : t('auth.changePassword.submit')}
          </Button>
        </form>
        <Button variant="ghost" onClick={onBack} className="w-full">
          {t('auth.forgot.back')}
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-5">
        <Field
          id="reset-email"
          label={t('auth.signIn.email')}
          error={errors.email && t('auth.errors.emailInvalid')}
        >
          <input
            id="reset-email"
            type="email"
            autoComplete="email"
            dir="ltr"
            className={inputClass}
            {...register('email')}
          />
        </Field>
        {status === 'sent' && (
          <p role="status" className="rounded-lg bg-success-50 px-3 py-2 text-sm text-success-700">
            {t('auth.forgot.sent')}
          </p>
        )}
        {status === 'requested' && (
          <p role="status" className="rounded-lg bg-success-50 px-3 py-2 text-sm text-success-700">{t('auth.forgot.requested')}</p>
        )}
        {status === 'pending' && (
          <p role="status" className="rounded-lg bg-warning-50 px-3 py-3 text-sm text-warning-700">
            {t('auth.forgot.pending')}
          </p>
        )}
        {(status === 'network' || status === 'unknown') && (
          <p role="alert" className="rounded-lg bg-error-50 px-3 py-2 text-sm text-error-700">
            {t(`auth.errors.${status}`)}
          </p>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Button type="submit" disabled={isSubmitting || checking} className="w-full">
            {isSubmitting ? t('auth.forgot.submitting') : t('auth.forgot.submit')}
          </Button>
          <Button type="button" variant="secondary" onClick={() => void requestApproval()} disabled={isSubmitting || checking} className="w-full">
            {checking ? t('common.loading') : t('auth.forgot.requestApproval')}
          </Button>
        </div>
      </form>
      <Button variant="ghost" onClick={onBack} className="w-full">
        {t('auth.forgot.back')}
      </Button>
    </div>
  );
}
