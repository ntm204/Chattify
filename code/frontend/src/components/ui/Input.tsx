import * as React from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: string;
  containerClassName?: string;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, error, containerClassName, ...props }, ref) => {
    return (
      <div className={cn("w-full flex flex-col mb-2.5", containerClassName)}>
        <input
          type={type}
          className={cn(
            "w-full px-4.5 py-3.75 bg-(--input-bg) border-[1.5px] border-(--input-border) rounded-(--radius) font-inherit text-[14.5px] leading-normal text-(--foreground) outline-none transition-all placeholder:text-(--text-muted) focus:border-(--input-focus) focus:shadow-[0_0_0_3px_rgba(0,0,0,0.07)]",
            error && "border-red-500/50",
            className,
          )}
          ref={ref}
          {...props}
        />
        {error && (
          <p className="mt-1 ml-1 text-xs text-red-500/80 font-medium">
            {error}
          </p>
        )}
      </div>
    );
  },
);
Input.displayName = "Input";

export { Input };
