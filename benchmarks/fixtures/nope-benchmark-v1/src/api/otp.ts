export async function sendOtp(req: any, twilio: any) {
  return twilio.sendSms(req.body.phone, "Your otp is 123456");
}
