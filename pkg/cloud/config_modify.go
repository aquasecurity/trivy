package cloud

import (
	"reflect"
	"strings"

	"golang.org/x/xerrors"
)

// Set sets a nested field in the Trivy Cloud config
func Set(attribute string, value any) error {
	config, err := Load()
	if err != nil {
		return xerrors.Errorf("failed to load Trivy Cloud config file: %w", err)
	}

	if err := setNestedField(reflect.ValueOf(config).Elem(), attribute, value); err != nil {
		return xerrors.Errorf("failed to set attribute %q: %w", attribute, err)
	}

	return config.Save()
}

// Unset sets a nested field in the Trivy Cloud config to its default value
func Unset(attribute string) error {
	config, err := Load()
	if err != nil {
		return xerrors.Errorf("failed to load Trivy Cloud config file: %w", err)
	}

	if err := unsetNestedField(reflect.ValueOf(config).Elem(), attribute); err != nil {
		return xerrors.Errorf("failed to unset attribute %q: %w", attribute, err)
	}

	return config.Save()
}

func unsetNestedField(value reflect.Value, attribute string) error {
	field, err := navigateToField(value, attribute)
	if err != nil {
		return err
	}

	defaultField, err := navigateToField(reflect.ValueOf(defaultConfig).Elem(), attribute)
	if err != nil {
		return err
	}

	field.Set(defaultField)
	return nil
}

// Get gets a nested field from the Trivy Cloud config
func Get(attribute string) (any, error) {
	return GetWithDefault[any](attribute, nil)
}

// GetWithDefault gets a nested field from the Trivy Cloud config with a default value
func GetWithDefault[T any](attribute string, defaultValue T) (T, error) {
	config, err := Load()
	if err != nil {
		return defaultValue, xerrors.Errorf("failed to load Trivy Cloud config file: %w", err)
	}

	field, err := navigateToField(reflect.ValueOf(config).Elem(), attribute)
	if err != nil {
		return defaultValue, xerrors.Errorf("failed to get attribute %q: %w", attribute, err)
	}

	return field.Interface().(T), nil
}

func setNestedField(v reflect.Value, path string, value any) error {
	field, err := navigateToField(v, path)
	if err != nil {
		return err
	}

	convertedValue, err := convertToType(value, field.Type())
	if err != nil {
		return xerrors.Errorf("failed to convert value: %w", err)
	}

	field.Set(convertedValue)
	return nil
}

func convertToType(value any, targetType reflect.Type) (reflect.Value, error) {
	valueReflect := reflect.ValueOf(value)

	if valueReflect.Type().AssignableTo(targetType) {
		return valueReflect, nil
	}

	if valueStr, ok := value.(string); ok {
		switch targetType.Kind() {
		case reflect.Bool:
			switch strings.ToLower(valueStr) {
			case "true", "1", "yes", "on":
				return reflect.ValueOf(true), nil
			case "false", "0", "no", "off":
				return reflect.ValueOf(false), nil
			default:
				return reflect.Value{}, xerrors.Errorf("invalid boolean value %q", valueStr)
			}
		case reflect.String:
			return reflect.ValueOf(valueStr), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return reflect.Value{}, xerrors.New("integer conversion from string not yet implemented")
		case reflect.Float32, reflect.Float64:
			return reflect.Value{}, xerrors.New("float conversion from string not yet implemented")
		}
	}

	return reflect.Value{}, xerrors.Errorf("cannot convert value of type %v to type %v", valueReflect.Type(), targetType)
}

func navigateToField(v reflect.Value, path string) (reflect.Value, error) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return reflect.Value{}, xerrors.New("empty attribute path")
	}

	for i, part := range parts {
		fieldName := yamlTagToFieldName(v, part)
		if fieldName == "" {
			return reflect.Value{}, xerrors.Errorf("field %q not found in config", part)
		}

		field := v.FieldByName(fieldName)
		if !field.IsValid() {
			return reflect.Value{}, xerrors.Errorf("field %q not found", fieldName)
		}
		if !field.CanSet() {
			return reflect.Value{}, xerrors.Errorf("field %q cannot be set", fieldName)
		}

		if i == len(parts)-1 {
			return field, nil
		}

		v = field
	}

	return reflect.Value{}, xerrors.New("unexpected end of path")
}

func yamlTagToFieldName(v reflect.Value, yamlTag string) string {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("yaml")
		tagName := strings.Split(tag, ",")[0]
		if tagName == yamlTag {
			return field.Name
		}
	}
	return ""
}
