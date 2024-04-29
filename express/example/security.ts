//reverses the original password to hash it (NEVER DO THAT! JUST FOR EASY SHOWCASE)
export function hash(password: string): string {
  return password.split("").reverse().join("");
}

//reverses the given password to compare it to hash (NEVER DO THAT! JUST FOR EASY SHOWCASE)
export function compare(password: string, hashedPassword: string): boolean {
  return password.split("").reverse().join("") === hashedPassword;
}
