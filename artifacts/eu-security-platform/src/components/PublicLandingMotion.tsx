import { useEffect } from "react";

/**
 * Adds small, one-time entrance transitions to the public landing page.
 * Content remains visible when motion is reduced or the animation module
 * cannot load; the animation never gates interaction or page content.
 */
export function PublicLandingMotion() {
  useEffect(() => {
    const root = document.querySelector<HTMLElement>(".public-page");
    const motionPreference = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (!root || motionPreference.matches) return;

    let cancelled = false;
    let context: { revert: () => void } | undefined;
    const stopForReducedMotion = () => {
      if (motionPreference.matches) context?.revert();
    };

    motionPreference.addEventListener?.("change", stopForReducedMotion);

    async function start() {
      const [{ gsap }, { ScrollTrigger }] = await Promise.all([
        import("gsap"),
        import("gsap/ScrollTrigger"),
      ]);
      if (cancelled || motionPreference.matches) return;

      gsap.registerPlugin(ScrollTrigger);
      context = gsap.context(() => {
        gsap.from(".public-page .hero-copy > *", {
          autoAlpha: 0,
          y: 12,
          duration: 0.42,
          stagger: 0.055,
          ease: "power2.out",
          clearProps: "opacity,visibility,transform",
        });

        gsap.utils
          .toArray<HTMLElement>(
            ".public-page .agent-flow li, .public-page .agent-risk-card, .public-page .available-row, .public-page .compliance-section",
          )
          .forEach((element) => {
            gsap.fromTo(
              element,
              { autoAlpha: 0, y: 14 },
              {
                autoAlpha: 1,
                y: 0,
                duration: 0.38,
                ease: "power2.out",
                clearProps: "opacity,visibility,transform",
                immediateRender: false,
                scrollTrigger: {
                  trigger: element,
                  start: "top 90%",
                  once: true,
                },
              },
            );
          });
      }, root!);
    }

    void start().catch((error: unknown) => {
      // A motion failure must not affect the page or conceal its content.
      console.warn("Public landing motion was unavailable.", error);
    });

    return () => {
      cancelled = true;
      motionPreference.removeEventListener?.("change", stopForReducedMotion);
      context?.revert();
    };
  }, []);

  return null;
}
