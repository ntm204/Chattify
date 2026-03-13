"use client";

import { useState } from "react";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import axios from "axios";

import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { authService } from "@/features/auth/services/auth.service";

const forgotSchema = z.object({
  email: z.string().min(1, "Please enter your email or phone number."),
});

type ForgotFormValues = z.infer<typeof forgotSchema>;

export default function ForgotPasswordPage() {
  const [isSuccess, setIsSuccess] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotFormValues>({
    resolver: zodResolver(forgotSchema),
    defaultValues: { email: "" },
  });

  const onSubmit = async (data: ForgotFormValues) => {
    try {
      setApiError(null);
      await authService.forgotPassword(data.email);
      setIsSuccess(true);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        setApiError(
          error.response?.data?.message || "Failed to send reset link.",
        );
      } else {
        setApiError("An unexpected error occurred.");
      }
    }
  };

  if (isSuccess) {
    return (
      <div className="w-full flex flex-col items-center animate-fade-up text-center pt-2 pb-1">
        <div className="w-13.5 h-13.5 bg-[#111] rounded-full flex items-center justify-center mb-4">
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#fff"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
        </div>
        <h2 className="text-[18px] font-bold mb-2">Check your inbox</h2>
        <p className="text-[13.5px] text-(--text-secondary) leading-relaxed">
          We&apos;ve sent a password reset link to your email. Check your spam
          folder if you don&apos;t see it.
        </p>
        <Button
          onClick={() => (window.location.href = "/login")}
          className="mt-5"
        >
          Back to Sign In
        </Button>
      </div>
    );
  }

  return (
    <div className="w-full animate-fade-up">
      <h1 className="text-[22px] font-bold text-(--foreground) text-center mb-5.5 tracking-[-0.3px]">
        Forgot Password
      </h1>

      <p className="text-[13.5px] text-(--text-secondary) text-center leading-relaxed mb-4.5">
        Enter your email or phone number and we&apos;ll send you a link to
        reset your password.
      </p>

      <form onSubmit={handleSubmit(onSubmit)} className="w-full">
        {apiError && (
          <div className="p-[10px_14px] bg-[#fee2e2] text-[#b91c1c] rounded-[10px] text-[13px] font-medium mb-3">
            {apiError}
          </div>
        )}

        <Input
          {...register("email")}
          placeholder="Email or Phone number"
          autoComplete="username"
          error={errors.email?.message}
        />

        <Button type="submit" isLoading={isSubmitting} className="mt-3">
          Send Reset Link
        </Button>
      </form>

      <div className="flex justify-center gap-3.5 mt-4">
        <Link
          href="/login"
          className="text-[13px] text-(--link-color) font-medium hover:opacity-75 transition-opacity"
        >
          Sign In
        </Link>
        <span className="text-[13px] text-(--text-muted) pointer-events-none">
          ·
        </span>
        <Link
          href="/register"
          className="text-[13px] text-(--link-color) font-medium hover:opacity-75 transition-opacity"
        >
          Create Account
        </Link>
      </div>
    </div>
  );
}
