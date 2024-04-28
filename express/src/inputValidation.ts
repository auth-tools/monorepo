type YesOrNo = "Y" | "N";

//upper-lower-numbers-special-length
export type PasswordValidationRules =
  `${YesOrNo}-${YesOrNo}-${YesOrNo}-${YesOrNo}-${number}`;

//the PasswordValidationRules parsed into their parts
export type ParsedPasswordValidationRules = {
  upper: boolean;
  lower: boolean;
  number: boolean;
  special: boolean;
  minLength: number;
};

//helperfunction that parses a PasswordValidationRules string into ParsedPasswordValidationRules form
export function parsePasswordRules(
  rules: PasswordValidationRules
): ParsedPasswordValidationRules {
  const parsedPasswordRules: ParsedPasswordValidationRules = {
    upper: true,
    lower: true,
    number: true,
    special: true,
    minLength: 8,
  };

  const splitRules = rules.split("-");

  if (splitRules[0] === "N") parsedPasswordRules.upper = false;
  if (splitRules[1] === "N") parsedPasswordRules.lower = false;
  if (splitRules[2] === "N") parsedPasswordRules.number = false;
  if (splitRules[3] === "N") parsedPasswordRules.special = false;
  parsedPasswordRules.minLength = Number(splitRules[4]);

  return parsedPasswordRules;
}

//builtin validator function for password, which validates by the criteria given with a PasswordValidationRules
export function validatePassword(
  password: string,
  rules: PasswordValidationRules
): boolean {
  //parse the rule
  const parsedRules = parsePasswordRules(rules);

  let valid = true;

  //check for uppercase letters if they are required in password
  if (parsedRules.upper) {
    if (!/[A-Z]/.test(password)) valid = false;
  }

  //check for lowercase letters if they are required in password
  if (parsedRules.lower) {
    if (!/[a-z]/.test(password)) valid = false;
  }

  //check for numbers if they are required in password
  if (parsedRules.number) {
    if (!/[0-9]/.test(password)) valid = false;
  }

  //check for special characters if they are required in password
  if (parsedRules.special) {
    if (!/[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password))
      valid = false;
  }

  //check that password is at least the length of minlegth set with the rule
  if (password.length < parsedRules.minLength) valid = false;

  return valid;
}

//builtin validator function for email, which validates by the a regex
export function validateEmail(email: string) {
  return /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(
    email
  );
}
