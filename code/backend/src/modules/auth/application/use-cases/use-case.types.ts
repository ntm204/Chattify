import { AuthResponse } from '../../domain/contracts/auth.contract';

export type FinalizeLoginArgs<TContext, TAction extends string = string> = {
  user: { id: string } & Record<string, unknown>;
  context: TContext;
  action: TAction;
  message: string;
  isNewUser?: boolean;
};

export type FinalizeLoginFn<TContext, TAction extends string = string> = (
  args: FinalizeLoginArgs<TContext, TAction>,
) => Promise<AuthResponse>;
