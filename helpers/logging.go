// Copyright 2018, Jon Hadfield <jon@lessknown.co.uk>
// This file is part of ape.

// ape is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// ape is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with ape.  If not, see <http://www.gnu.org/licenses/>.

package helpers

import (
	syslog "github.com/RackSec/srslog"
	golog "github.com/op/go-logging"
)

// Debug writes entry to provided loggers
func Debug(loggrs []interface{}, message string) {
	pushDirector("debug", message, loggrs)

}

// Info writes entry to provided loggers
func Info(loggrs []interface{}, message string) {
	pushDirector("info", message, loggrs)

}

// Notice writes entry to provided loggers
func Notice(loggrs []interface{}, message string) {
	pushDirector("notice", message, loggrs)

}

// Warn writes entry to provided loggers
func Warn(loggrs []interface{}, message string) {
	pushDirector("warn", message, loggrs)

}

// Error writes entry to provided loggers
func Error(loggrs []interface{}, message string) {
	pushDirector("error", message, loggrs)
}

// Critical writes entry to provided loggers
func Critical(loggrs []interface{}, message string) {
	pushDirector("critical", message, loggrs)
}

func pushSyslog(level, message string, sysLogger *syslog.Writer) {
	switch level {
	case "debug":
		_ = sysLogger.Debug(message)
	case "info":
		_ = sysLogger.Info(message)
	case "notice":
		_ = sysLogger.Notice(message)
	case "warn":
		_ = sysLogger.Warning(message)
	case "error":
		_ = sysLogger.Err(message)
	case "critical":
		_ = sysLogger.Crit(message)
	}
}

func pushFile(level, message string, fileLogger *golog.Logger) {
	switch level {
	case "debug":
		fileLogger.Debug(message)
	case "info":
		fileLogger.Info(message)
	case "notice":
		fileLogger.Notice(message)
	case "warn":
		fileLogger.Warning(message)
	case "error":
		fileLogger.Error(message)
	case "critical":
		fileLogger.Critical(message)
	}
}

func pushDirector(level, message string, loggrs []interface{}) {
	for _, loggr := range loggrs {
		if sysLogger, isSyslog := loggr.(*syslog.Writer); isSyslog {
			pushSyslog(level, message, sysLogger)
		}
		if fileLogger, isFileLogger := loggr.(*golog.Logger); isFileLogger {
			pushFile(level, message, fileLogger)
		}
	}
}
