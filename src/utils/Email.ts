import * as Brevo from "@getbrevo/brevo";
import {
  getPasswordResetEmailTemplate,
  getVerificationEmailTemplate,
} from "./emailTemplate.util";

export class EmailService {
  private apiInstance: Brevo.TransactionalEmailsApi;

  constructor() {
    this.apiInstance = new Brevo.TransactionalEmailsApi();
    console.log(process.env.BREVO_API_KEY!);
    this.apiInstance.setApiKey(
      Brevo.TransactionalEmailsApiApiKeys.apiKey,
      process.env.BREVO_API_KEY!,
    );
  }

  async sendVerification(name: string, to: string, url: string) {
    const template = getVerificationEmailTemplate(name, url);
    const email = {
      subject: template.subject,
      htmlContent: template.html,
      sender: { name: "Auth-kit", email: "muhammad.ahmad.raza789@gmail.com" },
      to: [{ email: to }],
    };

    try {
      return await this.apiInstance.sendTransacEmail(email);
    } catch (error) {
      console.error("Brevo Error:", error);
      throw error;
    }
  }

  async sendPasswordReset(name: string, to: string, url: string) {
    const template = getPasswordResetEmailTemplate(name, url);
    const email = {
      subject: template.subject,
      htmlContent: template.html,
      sender: { name: "Auth-kit", email: "muhammad.ahmad.raza789@gmail.com" },
      to: [{ email: to }],
    };

    try {
      return await this.apiInstance.sendTransacEmail(email);
    } catch (error) {
      console.error("Brevo Error:", error);
      throw error;
    }
  }
  static init() {
    return new EmailService();
  }
}
