type YesOrNo = "Y" | "N";

//upper-lower-numbers-special-length
export type PasswordValidationRules =
  `${YesOrNo}-${YesOrNo}-${YesOrNo}-${YesOrNo}-${number}`;
