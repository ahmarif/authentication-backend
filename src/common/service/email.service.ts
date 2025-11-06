import dotenv from "dotenv";
import { Analytics } from "@bentonow/bento-node-sdk";
import { signupConfirmTemplate } from "../templates/signupConfirm.template.js";
import { forgotPasswordTemplate } from "../templates/forgotPassword.template.js";
import { passwordResetSuccessTemplate } from "../templates/passwordResetSuccess.template.js";
import { subscribePromptTemplate } from "../templates/subscribe.template.js";

dotenv.config();

const bento = new Analytics({
  authentication: {
    publishableKey: process.env.BENTO_PUBLISHABLE_KEY!,
    secretKey: process.env.BENTO_SECRET_KEY!,
  },
  siteUuid: process.env.BENTO_SITE_UUID!,
});

type EmailTemplateType = "SIGNUP_CONFIRM" | "FORGOT_PASSWORD" | "PASSWORD_RESET_SUCCESS" | "SUBSCRIBE_PROMPT";

export const sendEmail = async (
  to: string,
  username: string,
  linkOrOtp: string,
  type: EmailTemplateType
) => {
  const companyName = process.env.COMPANY_NAME || "My Company";

  const colors = {
    primary: process.env.COLOR_PRIMARY || "#2907CA",
    secondary: process.env.COLOR_SECONDARY || "#EAE6FE",
    background: process.env.COLOR_BACKGROUND || "#F8F8F8",
  };

  let subject = "";
  let html = "";

  switch (type) {
    case "SIGNUP_CONFIRM":
      ({ subject, html } = signupConfirmTemplate(username, linkOrOtp, companyName, colors));
      break;
    case "FORGOT_PASSWORD":
      ({ subject, html } = forgotPasswordTemplate(username, linkOrOtp, companyName, colors));
      break;
    case "PASSWORD_RESET_SUCCESS":
      ({ subject, html } = passwordResetSuccessTemplate(username, linkOrOtp, companyName, colors));
      break;
    case "SUBSCRIBE_PROMPT":
      ({ subject, html } = subscribePromptTemplate(username, linkOrOtp, companyName, colors));
      break;

    default:
      throw new Error("Invalid email template type");
  }

  try {
    const response = await bento.V1.Batch.sendTransactionalEmails({
      emails: [
        {
          to: to,
          from: process.env.EMAIL_FROM || "updates@notifications.analyticsauditor.com",
          subject: subject,
          html_body: html,
          transactional: true,
        }
      ]
    });
    return response;
  } catch (err: any) {
    throw err;
  }
};
