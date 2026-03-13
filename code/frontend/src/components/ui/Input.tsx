import * as React from "react"
import { cn } from "@/lib/utils"

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
    error?: string;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, error, ...props }, ref) => {
    return (
      <div className="w-full flex flex-col mb-[10px]">
        <input
          type={type}
          className={cn(
            "w-full px-[18px] py-[15px] bg-[var(--input-bg)] border-[1.5px] border-[var(--input-border)] rounded-[var(--radius)] font-inherit text-[14.5px] text-[var(--foreground)] outline-none transition-all placeholder:text-[var(--text-muted)] focus:border-[var(--input-focus)] focus:shadow-[0_0_0_3px_rgba(0,0,0,0.07)]",
            error && "border-red-500/50",
            className
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
    )
  }
)
Input.displayName = "Input"

export { Input }
