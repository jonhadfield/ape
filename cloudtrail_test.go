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

package ape

import (
	"testing"

	"time"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	h "github.com/jonhadfield/ape/helpers"
	"github.com/jonhadfield/ape/root"
	. "github.com/smartystreets/goconvey/convey"
)

// MOCK CLOUDTRAIL CLIENT
type mockCloudtrailClient struct {
	cloudtrailiface.CloudTrailAPI
}

func (m *mockCloudtrailClient) DescribeTrails(input *cloudtrail.DescribeTrailsInput) (*cloudtrail.DescribeTrailsOutput, error) {
	trail := &cloudtrail.Trail{}
	var trailList []*cloudtrail.Trail
	trailList = append(trailList, trail)
	output := &cloudtrail.DescribeTrailsOutput{TrailList: trailList}
	return output, nil
}

func TestDescribeTrailsWithOne(t *testing.T) {
	t.Parallel()
	mockSvc := &mockCloudtrailClient{}
	var err error
	var describeTrailsOutput []*cloudtrail.Trail
	describeTrailsOutput, err = describeTrails(mockSvc)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if len(describeTrailsOutput) != 1 {
		t.Error("function should return a single trail")
	}
}

// MOCK CLOUDTRAIL CLIENT 1
// DescribeTrails: Return single trail without any data
// GetTrailStatus: Return empty status
type mockCloudtrailClient1 struct {
	cloudtrailiface.CloudTrailAPI
}

func (m *mockCloudtrailClient1) DescribeTrails(input *cloudtrail.DescribeTrailsInput) (*cloudtrail.DescribeTrailsOutput, error) {
	// trueVal := true
	trail := &cloudtrail.Trail{
		TrailARN: h.PtrToStr(""),
	}
	var trailList []*cloudtrail.Trail
	trailList = append(trailList, trail)
	output := &cloudtrail.DescribeTrailsOutput{TrailList: trailList}
	return output, nil
}

func (m *mockCloudtrailClient1) GetTrailStatus(input *cloudtrail.GetTrailStatusInput) (*cloudtrail.GetTrailStatusOutput, error) {
	output := &cloudtrail.GetTrailStatusOutput{}
	return output, nil
}

func TestFilterLatestCloudWatchLogsDeliveryTimeWithMissingUnit(t *testing.T) {
	t.Parallel()
	Convey("Given a filter with a missing unit", t, func() {
		var f = root.Filter{
			Criterion:  "LatestCloudWatchLogsDeliveryTime",
			Comparison: ">",
			Value:      "invalid value",
		}
		Convey("When the filter is passed", func() {
			var errWith error
			mockSvc := &mockCloudtrailClient1{}
			_, errWith = filterLatestCloudWatchLogsDeliveryTime(mockSvc, cloudtrail.Trail{Name: h.PtrToStr("bob")}, &f)
			Convey("an error should be returned", func() {
				So(errWith, ShouldNotEqual, nil)
			})
		})
	})
}

func TestFilterLatestCloudWatchLogsDeliveryTimeWithValueUnparseableToInt64(t *testing.T) {
	t.Parallel()
	Convey("Given a filter with a missing unit", t, func() {
		var f = root.Filter{
			Criterion:  "LatestCloudWatchLogsDeliveryTime",
			Comparison: ">",
			Unit:       "hours",
			Value:      "invalid value",
		}
		Convey("When the filter is passed", func() {
			var errWith error
			mockSvc := &mockCloudtrailClient1{}
			_, errWith = filterLatestCloudWatchLogsDeliveryTime(mockSvc, cloudtrail.Trail{Name: h.PtrToStr("bob")}, &f)
			Convey("an error should be returned", func() {
				So(errWith, ShouldNotEqual, nil)
			})
		})
	})
}

func TestFilterLatestCloudWatchLogsDeliveryTimeWhereDeliveryTimeIsZero(t *testing.T) {
	t.Parallel()
	Convey("Given a filter looking for Delivery Time older than one hour", t, func() {
		var f = root.Filter{
			Criterion:  "LatestCloudWatchLogsDeliveryTime",
			Comparison: ">",
			Unit:       "hours",
			Value:      "1",
		}
		Convey("When the trail has a nil time", func() {
			mockSvc := &mockCloudtrailClient1{}
			result, _ := filterLatestCloudWatchLogsDeliveryTime(mockSvc, cloudtrail.Trail{Name: h.PtrToStr("bob")}, &f)
			Convey("the result should be true", func() {
				So(result, ShouldBeTrue)
			})
		})
	})
}

// MOCK CLOUDTRAIL CLIENT 2
// DescribeTrails: Return single trail without any data
// GetTrailStatus: Return status with LatestCloudWatchLogsDeliveryTime set to

type mockCloudtrailClient2 struct {
	cloudtrailiface.CloudTrailAPI
}

func (m *mockCloudtrailClient2) DescribeTrails(input *cloudtrail.DescribeTrailsInput) (*cloudtrail.DescribeTrailsOutput, error) {
	trail := &cloudtrail.Trail{Name: h.PtrToStr("test")}
	var trailList []*cloudtrail.Trail
	trailList = append(trailList, trail)
	output := &cloudtrail.DescribeTrailsOutput{TrailList: trailList}
	return output, nil
}

func (m *mockCloudtrailClient2) GetTrailStatus(input *cloudtrail.GetTrailStatusInput) (*cloudtrail.GetTrailStatusOutput, error) {
	oneWeekAgo := time.Now().UTC().AddDate(0, 0, -7)
	output := &cloudtrail.GetTrailStatusOutput{
		LatestCloudWatchLogsDeliveryTime: &oneWeekAgo,
	}
	return output, nil
}

func TestFilterLatestCloudWatchLogsDeliveryTimeWhereDeliveryTimeIsSet(t *testing.T) {
	t.Parallel()
	Convey("Given a filter looking for Delivery Time less than one month", t, func() {
		var f = root.Filter{
			Criterion:  "LatestCloudWatchLogsDeliveryTime",
			Comparison: "<",
			Unit:       "days",
			Value:      "30",
		}
		Convey("When the trail has a latest delivery time of one week", func() {
			mockSvc := &mockCloudtrailClient2{}
			result, _ := filterLatestCloudWatchLogsDeliveryTime(mockSvc, cloudtrail.Trail{Name: h.PtrToStr("bob")}, &f)
			Convey("the result should be true", func() {
				So(result, ShouldBeTrue)
			})
		})
	})
}

type mockS3ClientForCloudtrail struct {
	s3iface.S3API
}

func (m mockS3ClientForCloudtrail) GetBucketLogging(*s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	le := s3.LoggingEnabled{
		TargetBucket: h.PtrToStr("valid-bucket"),
		TargetPrefix: h.PtrToStr("test"),
	}
	return &s3.GetBucketLoggingOutput{
		LoggingEnabled: &le,
	}, nil
}

func (m mockS3ClientForCloudtrail) ListBuckets(input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	s3Bucket := s3.Bucket{
		Name: h.PtrToStr("testBucket"),
	}
	var s3Buckets = []*s3.Bucket{&s3Bucket}
	return &s3.ListBucketsOutput{
		Buckets: s3Buckets,
	}, nil
}

func (m mockS3ClientForCloudtrail) AbortMultipartUpload(*s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
	return &s3.AbortMultipartUploadOutput{RequestCharged: h.PtrToStr("false")}, nil
}

func TestFilterBucketLoggingEnabled(t *testing.T) {
	t.Parallel()
	Convey("Given a filter looking for logging on a Cloudtrail bucket", t, func() {
		var f = root.Filter{
			Criterion: "BucketLoggingEnabled",
			Value:     "true",
		}
		Convey("When the trail's bucket has logging enabled", func() {
			mockS3Svc := mockS3ClientForCloudtrail{}
			filt := filterBucketLoggingEnabledInput{
				planItem: PlanItem{},
				trail: &cloudtrailTrail{
					trail: cloudtrail.Trail{
						S3BucketName: h.PtrToStr("testBucket"),
					},
				},
				filter:       &f,
				mockS3Client: mockS3Svc,
			}
			result, _ := filterBucketLoggingEnabled(nil, filt)
			Convey("the result should be true", func() {
				So(result, ShouldBeTrue)
			})
		})
	})
}
