type LogLevel = "debug" | "info" | "warn" | "error";

export class Logger {
  private capitalizeLogLevel: boolean;
  constructor(config?: { capitalizeLogLevel?: boolean }) {
    this.log = this.log.bind(this);
    this.capitalizeLogLevel = config?.capitalizeLogLevel ?? true;
  }

  public log(logLevel: LogLevel, message: string) {
    message.split("\n").forEach((line) => {
      console.log(
        `[${
          this.capitalizeLogLevel ? logLevel.toUpperCase() : logLevel
        }] ${line}`
      );
    });
  }
}
