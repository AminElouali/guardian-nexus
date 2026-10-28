import { AlertCircle, ArrowLeft } from 'lucide-react';
import { Link } from 'wouter';

export default function NotFound() {
  return (
    <main className="min-h-[100dvh] flex items-center justify-center bg-[#f7f5ef] px-5 py-16 text-[#203043]">
      <section className="w-full max-w-lg border border-[#ddd9cf] rounded-xl bg-[#fbfaf6] p-8 sm:p-10">
        <div className="mb-7 flex items-center gap-3">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-[#e9f0e7] text-[#28745b]">
            <AlertCircle size={20} />
          </span>
          <span className="font-mono text-[10px] uppercase tracking-[.14em] text-[#74847b]">Vigilant / 404</span>
        </div>
        <p className="font-mono text-xs text-[#28745b]">ERROR 404</p>
        <h1 className="mt-2 font-display text-3xl font-bold tracking-tight">No encontramos esta página.</h1>
        <p className="mt-3 text-sm leading-6 text-[#6d7880]">La dirección puede haber cambiado o quizá no exista. Vuelve al inicio para continuar.</p>
        <Link href="/" className="mt-7 inline-flex min-h-11 items-center gap-2 rounded-lg bg-[#28745b] px-4 text-sm font-semibold text-[#f8f6ef] hover:bg-[#1e5c48]" data-testid="link-not-found-home">
          <ArrowLeft size={16} /> Volver al inicio
        </Link>
      </section>
    </main>
  );
}
