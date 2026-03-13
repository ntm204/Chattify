"use client";

import { useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import axios from "axios";

import { useAuthStore } from "@/features/auth/store/auth.store";
import { authService } from "@/features/auth/services/auth.service";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

const registerSchema = z
  .object({
    name: z.string().min(2, "Name must be at least 2 characters."),
    email: z.string().email("Invalid email address."),
    password: z.string().min(6, "Password must be at least 6 characters."),
    confirmPassword: z.string().min(1, "Please confirm your password."),
    agree: z.boolean().refine((val) => val === true, {
      message: "Please accept the terms to continue.",
    }),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

type RegisterFormValues = z.infer<typeof registerSchema>;

export default function RegisterPage() {
  const router = useRouter();
  const setUser = useAuthStore((state) => state.setUser);
  const [apiError, setApiError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isSubmitting },
  } = useForm<RegisterFormValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      name: "",
      email: "",
      password: "",
      confirmPassword: "",
      agree: false,
    },
  });

  const password = useWatch({ control, name: "password" });

  const passwordStrength = useMemo(() => {
    if (!password) return 0;
    let score = 0;
    if (password.length >= 6) score++;
    if (password.length >= 10) score++;
    if (/[A-Z]/.test(password) && /[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  }, [password]);

  const strengthColor = useMemo(() => {
    if (passwordStrength <= 1) return "bg-[#e55]";
    if (passwordStrength === 2) return "bg-[#f90]";
    return "bg-[#3c3]";
  }, [passwordStrength]);

  const onSubmit = async (data: RegisterFormValues) => {
    try {
      setApiError(null);
      const response = await authService.register({
        name: data.name,
        email: data.email,
        password: data.password,
      });

      setUser(response.data.user);
      router.push("/");
    } catch (error) {
      if (axios.isAxiosError(error)) {
        setApiError(
          error.response?.data?.message ||
            "Registration failed. Please try again.",
        );
      } else {
        setApiError("An unexpected error occurred.");
      }
    }
  };

  return (
    <div className="w-full animate-fade-up">
      <h1 className="text-[22px] font-bold text-(--foreground) text-center mb-5.5 tracking-[-0.3px]">
        Create Account
      </h1>

      <form onSubmit={handleSubmit(onSubmit)} className="w-full">
        {apiError && (
          <div className="p-[10px_14px] bg-[#fee2e2] text-[#b91c1c] rounded-[10px] text-[13px] font-medium mb-3">
            {apiError}
          </div>
        )}

        <Input
          {...register("name")}
          placeholder="Full name"
          autoComplete="name"
          error={errors.name?.message}
        />

        <Input
          {...register("email")}
          placeholder="Email or Phone number"
          autoComplete="username"
          error={errors.email?.message}
        />

        <div className="mb-2.5">
          <Input
            {...register("password")}
            type="password"
            placeholder="Password"
            autoComplete="new-password"
            containerClassName="mb-0"
            error={errors.password?.message}
          />
          <div className="mt-1.75 flex gap-1">
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className={`flex-1 h-0.75 rounded-full transition-colors duration-250 ${
                  i <= passwordStrength ? strengthColor : "bg-[#d8d8d8]"
                }`}
              />
            ))}
          </div>
        </div>

        <Input
          {...register("confirmPassword")}
          type="password"
          placeholder="Confirm password"
          autoComplete="new-password"
          error={errors.confirmPassword?.message}
        />

        <div className="mt-2 flex items-start gap-2.25">
          <input
            {...register("agree")}
            type="checkbox"
            id="agree-terms"
            className="mt-1 w-3.75 h-3.75 accent-(--foreground) cursor-pointer"
          />
          <label
            htmlFor="agree-terms"
            className="text-[13px] text-(--text-secondary) leading-normal cursor-pointer select-none"
          >
            I agree to the{" "}
            <Link href="#" className="text-(--link-color) hover:opacity-75">
              Terms of Use
            </Link>{" "}
            and{" "}
            <Link href="#" className="text-(--link-color) hover:opacity-75">
              Privacy Policy
            </Link>
          </label>
        </div>
        {errors.agree && (
          <p className="mt-1 ml-1 text-xs text-red-500/80 font-medium">
            {errors.agree.message}
          </p>
        )}

        <Button type="submit" isLoading={isSubmitting} className="mt-3">
          Sign Up
        </Button>
      </form>

      <div className="mt-4 flex justify-center">
        <Link
          href="/login"
          className="text-[13px] text-(--link-color) font-medium hover:opacity-75 transition-opacity"
        >
          Already have an account? Sign In
        </Link>
      </div>
    </div>
  );
}
