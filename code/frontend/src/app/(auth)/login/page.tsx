"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import axios from "axios";

import { useAuthStore } from "@/features/auth/store/auth.store";
import { authService } from "@/features/auth/services/auth.service";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

const loginSchema = z.object({
  email: z.string().min(1, "Please enter your email or phone number."),
  password: z.string().min(1, "Please enter your password."),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const router = useRouter();
  const setUser = useAuthStore((state) => state.setUser);
  const [apiError, setApiError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  const onSubmit = async (data: LoginFormValues) => {
    try {
      setApiError(null);
      const response = await authService.login(data);

      if (response.data.requires2FA) {
        return;
      }

      setUser(response.data.user);
      router.push("/");
    } catch (error) {
      if (axios.isAxiosError(error)) {
        setApiError(
          error.response?.data?.message ||
            "Invalid credentials. Please try again.",
        );
      } else {
        setApiError("An unexpected error occurred.");
      }
    }
  };

  return (
    <div className="w-full animate-fade-up">
      <h1 className="text-[22px] font-bold text-(--foreground) text-center mb-5.5 tracking-[-0.3px]">
        Sign In
      </h1>

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

        <Input
          {...register("password")}
          type="password"
          placeholder="Password"
          autoComplete="current-password"
          error={errors.password?.message}
        />

        <Button type="submit" isLoading={isSubmitting} className="mt-3">
          Sign In
        </Button>
      </form>

      <div className="flex justify-center gap-3.5 mt-4">
        <Link
          href="/register"
          className="text-[13px] text-(--link-color) font-medium hover:opacity-75 transition-opacity"
        >
          Sign Up
        </Link>
        <span className="text-[13px] text-(--text-muted) pointer-events-none">
          ·
        </span>
        <Link
          href="/forgot-password"
          className="text-[13px] text-(--link-color) font-medium hover:opacity-75 transition-opacity"
        >
          Forgot Password
        </Link>
        <span className="text-[13px] text-(--text-muted) pointer-events-none">
          ·
        </span>
        <Link
          href="#"
          className="text-[13px] text-(--link-color) font-medium hover:opacity-75 transition-opacity"
        >
          Contact Us
        </Link>
      </div>
    </div>
  );
}
